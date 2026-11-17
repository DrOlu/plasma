"""OpenAPI 3.1 description of the `plasma serve` HTTP API.

The spec is intentionally small: four routes, two auth schemes and the
envelopes the server actually returns. `POST /v1/exec` is generic by
design — the full command surface is discoverable at `GET /v1/commands`,
not enumerated here.
"""

from __future__ import annotations

from . import __version__

SPEC: dict = {
    "openapi": "3.1.0",
    "info": {
        "title": "Plasma HTTP API",
        "version": __version__,
        "description": (
            "The full Plasma CLI over an authenticated HTTP API. "
            "`POST /v1/exec` takes an argv list and runs it through the real "
            "CLI parser; `GET /v1/commands` returns the command tree. "
            "The API is an alternative to WinRM or SSH."
        ),
        "license": {"name": "MIT"},
    },
    "servers": [
        {
            "url": "http://{host}:{port}",
            "description": "A Plasma node running `plasma serve`",
            "variables": {
                "host": {"default": "127.0.0.1"},
                "port": {"default": "9999"},
            },
        }
    ],
    "security": [{"bearerAuth": []}, {"apiKeyAuth": []}],
    "tags": [
        {"name": "health", "description": "Liveness and version"},
        {"name": "discovery", "description": "Command tree and OpenAPI"},
        {"name": "exec", "description": "Run one CLI argv"},
    ],
    "paths": {
        "/healthz": {
            "get": {
                "tags": ["health"],
                "summary": "Liveness",
                "description": "Unauthenticated liveness probe. Returns no host data.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "The server is alive",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Health"}
                            }
                        },
                    },
                    "405": {"$ref": "#/components/responses/MethodNotAllowed"},
                },
            }
        },
        "/v1/version": {
            "get": {
                "tags": ["health"],
                "summary": "Version and runtime",
                "responses": {
                    "200": {
                        "description": "Version, Python, platform and read-only flag",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Version"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "405": {"$ref": "#/components/responses/MethodNotAllowed"},
                },
            }
        },
        "/v1/commands": {
            "get": {
                "tags": ["discovery"],
                "summary": "Full CLI command tree",
                "description": (
                    "Every command path the CLI accepts, with options, "
                    "mutating flags and long-running markers."
                ),
                "responses": {
                    "200": {
                        "description": "The command tree",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CommandTree"}
                            }
                        },
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "405": {"$ref": "#/components/responses/MethodNotAllowed"},
                },
            }
        },
        "/v1/exec": {
            "post": {
                "tags": ["exec"],
                "summary": "Run one CLI argv",
                "description": (
                    "The argv is parsed by the real CLI parser before anything "
                    "runs. A completed command returns HTTP 200 even when its "
                    "exit code is non-zero; inspect `exit_code` and `ok`. "
                    "HTTP 4xx means the request was refused before the command ran."
                ),
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ExecRequest"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "The command completed",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ExecResult"}
                            }
                        },
                    },
                    "400": {"$ref": "#/components/responses/BadRequest"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "404": {"$ref": "#/components/responses/NotFound"},
                    "405": {"$ref": "#/components/responses/MethodNotAllowed"},
                    "413": {"$ref": "#/components/responses/PayloadTooLarge"},
                    "500": {"$ref": "#/components/responses/InternalError"},
                    "504": {"$ref": "#/components/responses/Timeout"},
                },
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "`Authorization: Bearer <key>`",
            },
            "apiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "The same key in the `X-API-Key` header",
            },
        },
        "schemas": {
            "Health": {
                "type": "object",
                "required": ["ok", "product", "version"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "product": {"type": "string", "const": "Plasma"},
                    "version": {"type": "string"},
                },
            },
            "Version": {
                "type": "object",
                "required": ["ok", "product", "version", "python", "platform",
                             "frozen", "read_only"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "product": {"type": "string", "const": "Plasma"},
                    "version": {"type": "string"},
                    "python": {"type": "string"},
                    "platform": {"type": "string"},
                    "frozen": {"type": "boolean"},
                    "read_only": {"type": "boolean"},
                },
            },
            "Option": {
                "type": "object",
                "required": ["flags", "dest", "required", "default", "choices",
                             "help"],
                "properties": {
                    "flags": {"type": "array", "items": {"type": "string"}},
                    "dest": {"type": "string"},
                    "required": {"type": "boolean"},
                    "default": {"description": "The argparse default, when scalar"},
                    "choices": {
                        "type": ["array", "null"],
                        "items": {"type": "string"},
                    },
                    "help": {"type": "string"},
                },
            },
            "Positional": {
                "type": "object",
                "required": ["name", "required", "nargs", "choices", "help"],
                "properties": {
                    "name": {"type": "string"},
                    "required": {"type": "boolean"},
                    "nargs": {"type": ["string", "null"]},
                    "choices": {
                        "type": ["array", "null"],
                        "items": {"type": "string"},
                    },
                    "help": {"type": "string"},
                },
            },
            "Command": {
                "type": "object",
                "required": ["path", "help", "options", "positionals",
                             "long_running", "mutating"],
                "properties": {
                    "path": {"type": "array", "items": {"type": "string"}},
                    "help": {"type": "string"},
                    "options": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Option"},
                    },
                    "positionals": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Positional"},
                    },
                    "long_running": {"type": "boolean"},
                    "mutating": {"type": "boolean"},
                },
            },
            "CommandTree": {
                "type": "object",
                "required": ["ok", "version", "root", "commands"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "version": {"type": "string"},
                    "root": {"$ref": "#/components/schemas/Command"},
                    "commands": {
                        "type": "array",
                        "items": {"$ref": "#/components/schemas/Command"},
                    },
                },
            },
            "ExecRequest": {
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["argv"],
                        "properties": {
                            "argv": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 1,
                                "maxItems": 64,
                            }
                        },
                        "additionalProperties": False,
                    },
                    {
                        "type": "object",
                        "required": ["command"],
                        "properties": {
                            "command": {
                                "oneOf": [
                                    {"type": "string"},
                                    {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                ]
                            },
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                        "additionalProperties": False,
                    },
                ]
            },
            "ExecResult": {
                "type": "object",
                "required": ["ok", "exit_code", "command", "argv", "stdout",
                             "stderr", "truncated", "duration_ms"],
                "properties": {
                    "ok": {"type": "boolean"},
                    "exit_code": {"type": "integer"},
                    "command": {"type": "string"},
                    "argv": {"type": "array", "items": {"type": "string"}},
                    "stdout": {"type": "string"},
                    "stderr": {"type": "string"},
                    "result": {
                        "description": "Parsed stdout when it is JSON, otherwise null"
                    },
                    "truncated": {"type": "boolean"},
                    "duration_ms": {"type": "number"},
                },
            },
            "Error": {
                "type": "object",
                "required": ["ok", "code", "error"],
                "properties": {
                    "ok": {"type": "boolean", "const": False},
                    "code": {"type": "string"},
                    "error": {"type": "string"},
                },
            },
        },
        "responses": {
            "BadRequest": {
                "description": "The request was malformed or the argv was invalid",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "Unauthorized": {
                "description": "A valid API key is required",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "Forbidden": {
                "description": "The command is refused in read-only mode",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "NotFound": {
                "description": "No route for this path",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "MethodNotAllowed": {
                "description": "Only GET and POST are supported",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "PayloadTooLarge": {
                "description": "The request body exceeds the configured limit",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "InternalError": {
                "description": "The server could not run the command",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
            "Timeout": {
                "description": "The command exceeded the configured timeout",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Error"}
                    }
                },
            },
        },
    },
}
