import json
import pathlib
import re
import shutil
import tempfile
import textwrap
from contextlib import contextmanager
from pathlib import Path

from click.testing import CliRunner

from langgraph_cli.cli import cli, prepare_args_and_stdin
from langgraph_cli.config import Config, _get_pip_cleanup_lines, validate_config
from langgraph_cli.docker import DEFAULT_POSTGRES_URI, DockerCapabilities, Version
from langgraph_cli.util import clean_empty_lines

FORMATTED_CLEANUP_LINES = _get_pip_cleanup_lines(
    install_cmd="uv pip install --system",
    to_uninstall=("pip", "setuptools", "wheel"),
    pip_installer="uv",
)
DEFAULT_DOCKER_CAPABILITIES = DockerCapabilities(
    version_docker=Version(26, 1, 1),
    version_compose=Version(2, 27, 0),
    healthcheck_start_interval=True,
)


@contextmanager
def temporary_config_folder(config_content: dict, levels: int = 0):
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    try:
        # Define the path for the config.json file
        config_path = Path(temp_dir) / f"{'a/' * levels}config.json"
        # Ensure the parent directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Write the provided dictionary content to config.json
        with open(config_path, "w", encoding="utf-8") as config_file:
            json.dump(config_content, config_file)

        # Yield the temporary directory path for use within the context
        yield config_path.parent
    finally:
        # Cleanup the temporary directory and its contents
        shutil.rmtree(temp_dir)


def test_prepare_args_and_stdin() -> None:
    # this basically serves as an end-to-end test for using config and docker helpers
    config_path = pathlib.Path(__file__).parent / "langgraph.json"
    config = validate_config(
        Config(dependencies=[".", "../../.."], graphs={"agent": "agent.py:graph"})
    )
    port = 8000
    debugger_port = 8001
    debugger_graph_url = f"http://127.0.0.1:{port}"

    actual_args, actual_stdin = prepare_args_and_stdin(
        capabilities=DEFAULT_DOCKER_CAPABILITIES,
        config_path=config_path,
        config=config,
        docker_compose=pathlib.Path("custom-docker-compose.yml"),
        port=port,
        debugger_port=debugger_port,
        debugger_base_url=debugger_graph_url,
        watch=True,
    )

    expected_args = [
        "--project-directory",
        str(pathlib.Path(__file__).parent.absolute()),
        "-f",
        "custom-docker-compose.yml",
        "-f",
        "-",
    ]
    expected_stdin = f"""volumes:
    langgraph-data:
        driver: local
services:
    langgraph-redis:
        image: redis:6
        healthcheck:
            test: redis-cli ping
            interval: 5s
            timeout: 1s
            retries: 5
    langgraph-postgres:
        image: pgvector/pgvector:pg16
        ports:
            - "5433:5432"
        environment:
            POSTGRES_DB: postgres
            POSTGRES_USER: postgres
            POSTGRES_PASSWORD: postgres
        command:
            - postgres
            - -c
            - shared_preload_libraries=vector
        volumes:
            - langgraph-data:/var/lib/postgresql/data
        healthcheck:
            test: pg_isready -U postgres
            start_period: 10s
            timeout: 1s
            retries: 5
            interval: 60s
            start_interval: 1s
    langgraph-debugger:
        image: langchain/langgraph-debugger
        restart: on-failure
        depends_on:
            langgraph-postgres:
                condition: service_healthy
        ports:
            - "{debugger_port}:3968"
        environment:
            VITE_STUDIO_LOCAL_GRAPH_URL: {debugger_graph_url}
    langgraph-api:
        ports:
            - "8000:8000"
        depends_on:
            langgraph-redis:
                condition: service_healthy
            langgraph-postgres:
                condition: service_healthy
        environment:
            REDIS_URI: redis://langgraph-redis:6379
            POSTGRES_URI: {DEFAULT_POSTGRES_URI}
        healthcheck:
            test: python /api/healthcheck.py
            interval: 60s
            start_interval: 1s
            start_period: 10s
        
        pull_policy: build
        build:
            context: .
            additional_contexts:
                - cli_1: {str(pathlib.Path(__file__).parent.parent.parent.parent.absolute())}
            dockerfile_inline: |
                FROM langchain/langgraph-api:3.11
                # -- Adding local package . --
                ADD . /deps/cli
                # -- End of local package . --
                # -- Adding local package ../../.. --
                COPY --from=cli_1 . /deps/cli_1
                # -- End of local package ../../.. --
                # -- Installing all local dependencies --
                RUN PYTHONDONTWRITEBYTECODE=1 uv pip install --system --no-cache-dir -c /api/constraints.txt -e /deps/*
                # -- End of local dependencies install --
                ENV LANGSERVE_GRAPHS='{{"agent": "agent.py:graph"}}'
{textwrap.indent(textwrap.dedent(FORMATTED_CLEANUP_LINES), "                ")}
                WORKDIR /deps/cli
        
        develop:
            watch:
                - path: langgraph.json
                  action: rebuild
                - path: .
                  action: rebuild
                - path: ../../..
                  action: rebuild\
"""
    assert actual_args == expected_args
    assert clean_empty_lines(actual_stdin) == expected_stdin


def test_prepare_args_and_stdin_with_image() -> None:
    # this basically serves as an end-to-end test for using config and docker helpers
    config_path = pathlib.Path(__file__).parent / "langgraph.json"
    config = validate_config(
        Config(dependencies=[".", "../../.."], graphs={"agent": "agent.py:graph"})
    )
    port = 8000
    debugger_port = 8001
    debugger_graph_url = f"http://127.0.0.1:{port}"

    actual_args, actual_stdin = prepare_args_and_stdin(
        capabilities=DEFAULT_DOCKER_CAPABILITIES,
        config_path=config_path,
        config=config,
        docker_compose=pathlib.Path("custom-docker-compose.yml"),
        port=port,
        debugger_port=debugger_port,
        debugger_base_url=debugger_graph_url,
        watch=True,
        image="my-cool-image",
    )

    expected_args = [
        "--project-directory",
        str(pathlib.Path(__file__).parent.absolute()),
        "-f",
        "custom-docker-compose.yml",
        "-f",
        "-",
    ]
    expected_stdin = f"""volumes:
    langgraph-data:
        driver: local
services:
    langgraph-redis:
        image: redis:6
        healthcheck:
            test: redis-cli ping
            interval: 5s
            timeout: 1s
            retries: 5
    langgraph-postgres:
        image: pgvector/pgvector:pg16
        ports:
            - "5433:5432"
        environment:
            POSTGRES_DB: postgres
            POSTGRES_USER: postgres
            POSTGRES_PASSWORD: postgres
        command:
            - postgres
            - -c
            - shared_preload_libraries=vector
        volumes:
            - langgraph-data:/var/lib/postgresql/data
        healthcheck:
            test: pg_isready -U postgres
            start_period: 10s
            timeout: 1s
            retries: 5
            interval: 60s
            start_interval: 1s
    langgraph-debugger:
        image: langchain/langgraph-debugger
        restart: on-failure
        depends_on:
            langgraph-postgres:
                condition: service_healthy
        ports:
            - "{debugger_port}:3968"
        environment:
            VITE_STUDIO_LOCAL_GRAPH_URL: {debugger_graph_url}
    langgraph-api:
        ports:
            - "8000:8000"
        depends_on:
            langgraph-redis:
                condition: service_healthy
            langgraph-postgres:
                condition: service_healthy
        environment:
            REDIS_URI: redis://langgraph-redis:6379
            POSTGRES_URI: {DEFAULT_POSTGRES_URI}
        image: my-cool-image
        healthcheck:
            test: python /api/healthcheck.py
            interval: 60s
            start_interval: 1s
            start_period: 10s
        
        
        develop:
            watch:
                - path: langgraph.json
                  action: rebuild
                - path: .
                  action: rebuild
                - path: ../../..
                  action: rebuild\
"""
    assert actual_args == expected_args
    assert clean_empty_lines(actual_stdin) == expected_stdin


def test_version_option() -> None:
    """Test the --version option of the CLI."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])

    # Verify that the command executed successfully
    assert result.exit_code == 0, "Expected exit code 0 for --version option"

    # Check that the output contains the correct version information
    assert "LangGraph CLI, version" in result.output, (
        "Expected version information in output"
    )


def test_dockerfile_command_basic() -> None:
    """Test the 'dockerfile' command with basic configuration."""
    runner = CliRunner()
    config_content = {
        "python_version": "3.11",
        "graphs": {"agent": "agent.py:graph"},
        "dependencies": ["."],
    }

    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"

        result = runner.invoke(
            cli,
            ["dockerfile", str(save_path), "--config", str(temp_dir / "config.json")],
        )

        # Assert command was successful
        assert result.exit_code == 0, result.output
        assert "✅ Created: Dockerfile" in result.output

        # Check if Dockerfile was created
        assert save_path.exists()


def test_dockerfile_command_new_style_config() -> None:
    """Test `dockerfile` command with a new style config.

    This config format allows specifying agent data as a dictionary.
    {
        "graphs": {
            "agent1": {
                "path": ... # path to graph definition,
                ... # other fields
            }
        }
    }
    """
    runner = CliRunner()
    config_content = {
        "dependencies": ["./my_agent"],
        "graphs": {
            "agent": {
                "path": "./my_agent/agent.py:graph",
                "description": "This is a test agent",
            }
        },
        "env": ".env",
    }
    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"
        # Add agent.py file
        agent_path = temp_dir / "my_agent" / "agent.py"
        agent_path.parent.mkdir(parents=True, exist_ok=True)
        agent_path.touch()

        result = runner.invoke(
            cli,
            ["dockerfile", str(save_path), "--config", str(temp_dir / "config.json")],
        )

        # Assert command was successful
        assert result.exit_code == 0, result.output
        assert "✅ Created: Dockerfile" in result.output

        # Check if Dockerfile was created
        assert save_path.exists()


def test_dockerfile_command_with_base_image() -> None:
    """Test the 'dockerfile' command with a base image."""
    runner = CliRunner()
    config_content = {
        "python_version": "3.11",
        "graphs": {"agent": "agent.py:graph"},
        "dependencies": ["."],
        "base_image": "langchain/langgraph-server:0.2",
    }
    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"
        agent_path = temp_dir / "agent.py"
        agent_path.parent.mkdir(parents=True, exist_ok=True)
        agent_path.touch()

        result = runner.invoke(
            cli,
            ["dockerfile", str(save_path), "--config", str(temp_dir / "config.json")],
        )

        assert result.exit_code == 0, result.output
        assert "✅ Created: Dockerfile" in result.output

        assert save_path.exists()
        with open(save_path) as f:
            dockerfile = f.read()
            assert re.match("FROM langchain/langgraph-server:0.2-py3.*", dockerfile)


def test_dockerfile_command_with_docker_compose() -> None:
    """Test the 'dockerfile' command with Docker Compose configuration."""
    runner = CliRunner()
    config_content = {
        "dependencies": ["./my_agent"],
        "graphs": {"agent": "./my_agent/agent.py:graph"},
        "env": ".env",
    }
    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"
        # Add agent.py file
        agent_path = temp_dir / "my_agent" / "agent.py"
        agent_path.parent.mkdir(parents=True, exist_ok=True)
        agent_path.touch()

        result = runner.invoke(
            cli,
            [
                "dockerfile",
                str(save_path),
                "--config",
                str(temp_dir / "config.json"),
                "--add-docker-compose",
            ],
        )

        # Assert command was successful
        assert result.exit_code == 0
        assert "✅ Created: Dockerfile" in result.output
        assert "✅ Created: .dockerignore" in result.output
        assert "✅ Created: docker-compose.yml" in result.output
        assert (
            "✅ Created: .env" in result.output or "➖ Skipped: .env" in result.output
        )
        assert "🎉 Files generated successfully" in result.output

        # Check if Dockerfile, .dockerignore, docker-compose.yml, and .env were created
        assert save_path.exists()
        assert (temp_dir / ".dockerignore").exists()
        assert (temp_dir / "docker-compose.yml").exists()
        assert (temp_dir / ".env").exists() or "➖ Skipped: .env" in result.output


def test_dockerfile_command_with_bad_config() -> None:
    """Test the 'dockerfile' command with basic configuration."""
    runner = CliRunner()
    config_content = {
        "node_version": "20"  # Add any other necessary configuration fields
    }

    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"

        result = runner.invoke(
            cli,
            ["dockerfile", str(save_path), "--config", str(temp_dir / "conf.json")],
        )

        # Assert command was successful
        assert result.exit_code == 2
        assert "conf.json' does not exist" in result.output


def test_dockerfile_command_shows_wolfi_warning() -> None:
    """Test the 'dockerfile' command shows warning when image_distro is not wolfi."""
    runner = CliRunner()
    config_content = {
        "python_version": "3.11",
        "graphs": {"agent": "agent.py:graph"},
        "dependencies": ["."],
        # No image_distro specified - should default to debian and show warning
    }

    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"
        agent_path = temp_dir / "agent.py"
        agent_path.touch()

        result = runner.invoke(
            cli,
            ["dockerfile", str(save_path), "--config", str(temp_dir / "config.json")],
        )

        # Assert command was successful
        assert result.exit_code == 0, result.output

        # Check that warning is shown
        assert "Security Recommendation" in result.output
        assert "Wolfi Linux" in result.output
        assert "image_distro" in result.output
        assert "wolfi" in result.output


def test_dockerfile_command_no_wolfi_warning_when_wolfi_set() -> None:
    """Test the 'dockerfile' command does NOT show warning when image_distro is wolfi."""
    runner = CliRunner()
    config_content = {
        "python_version": "3.11",
        "graphs": {"agent": "agent.py:graph"},
        "dependencies": ["."],
        "image_distro": "wolfi",  # Explicitly set to wolfi - should not show warning
    }

    with temporary_config_folder(config_content) as temp_dir:
        save_path = temp_dir / "Dockerfile"
        agent_path = temp_dir / "agent.py"
        agent_path.touch()

        result = runner.invoke(
            cli,
            ["dockerfile", str(save_path), "--config", str(temp_dir / "config.json")],
        )

        # Assert command was successful
        assert result.exit_code == 0, result.output

        # Check that warning is NOT shown
        assert "Security Recommendation" not in result.output
        assert "Wolfi Linux" not in result.output


def test_build_command_shows_wolfi_warning() -> None:
    """Test the 'build' command shows warning when image_distro is not wolfi."""
    runner = CliRunner()
    config_content = {
        "python_version": "3.11",
        "graphs": {"agent": "agent.py:graph"},
        "dependencies": ["."],
        # No image_distro specified - should default to debian and show warning
    }

    with temporary_config_folder(config_content) as temp_dir:
        agent_path = temp_dir / "agent.py"
        agent_path.touch()

        # Mock docker command since we don't want to actually build
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "build",
                    "--tag",
                    "test-image",
                    "--config",
                    str(temp_dir / "config.json"),
                ],
                catch_exceptions=True,
            )

        # The command will fail because docker isn't available or we're mocking,
        # but we should still see the warning before it fails
        assert "Security Recommendation" in result.output
        assert "Wolfi Linux" in result.output
        assert "image_distro" in result.output
        assert "wolfi" in result.output


def test_build_generate_proper_build_context():
    runner = CliRunner()
    config_content = {
        "python_version": "3.11",
        "graphs": {"agent": "agent.py:graph"},
        "dependencies": [".", "../../..", "../.."],
        "image_distro": "wolfi",
    }

    with temporary_config_folder(config_content, levels=3) as temp_dir:
        agent_path = temp_dir / "agent.py"
        agent_path.touch()

        # Mock docker command since we don't want to actually build
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "build",
                    "--tag",
                    "test-image",
                    "--config",
                    str(temp_dir / "config.json"),
                ],
                catch_exceptions=True,
            )

        build_context_pattern = re.compile(r"--build-context\s+(\w+)=([^\s]+)")

        build_contexts = re.findall(build_context_pattern, result.output)
        assert len(build_contexts) == 2, (
            f"Expected 2 build contexts, but found {len(build_contexts)}"
        )
