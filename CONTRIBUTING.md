# Contributing to Frida Game Hacking MCP

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Include Python version, Frida version, OS
3. Steps to reproduce
4. Expected vs actual behavior

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run linting: `ruff check src/`
5. Commit with clear messages
6. Push and create a PR

## Development Setup

```bash
git clone https://github.com/0xhackerfren/frida-game-hacking-mcp.git
cd frida-game-hacking-mcp
python -m venv venv
venv\Scripts\activate  # Windows
pip install -e ".[dev]"
python -m frida_game_hacking_mcp
```

## Code Style

- Follow PEP 8
- Use type hints
- Document functions with docstrings
- Keep lines under 100 characters

## Adding New Tools

1. Add function with `@mcp.tool()` decorator
2. Include comprehensive docstring
3. Handle errors gracefully
4. Update documentation

## Commit Messages

Format: `type: description`

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring

## License

Contributions licensed under MIT License.

