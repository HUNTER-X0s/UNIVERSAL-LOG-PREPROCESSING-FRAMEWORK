"""Process entrypoint for the Phase 1 API shell."""

import uvicorn
from ulpf_platform.config import get_settings

from ulpf_api.app import create_app


def main() -> None:
    """Run the API with validated environment configuration."""
    settings = get_settings()
    uvicorn.run(
        create_app(settings),
        host="0.0.0.0",
        port=8080,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
