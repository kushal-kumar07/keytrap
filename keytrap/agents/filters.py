"""Shared file filters: keep binary and generated files out of the text scanners."""

from __future__ import annotations

from pathlib import PurePosixPath

BINARY_EXTENSIONS = frozenset(
	{
		# images
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".tif", ".psd",
		".heic", ".avif", ".icns",
		# fonts
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		# audio / video
		".mp3", ".wav", ".ogg", ".flac", ".mp4", ".mov", ".avi", ".mkv", ".webm",
		# documents / archives / binaries
		".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war",
		".class", ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".bin", ".dat", ".pyc",
		".sqlite", ".db", ".keystore", ".jks", ".xcassets", ".car", ".nib", ".storyboardc",
		".mlmodel", ".onnx", ".pb", ".npy", ".parquet",
	}
)

# Generated or vendored files full of hashes and long tokens that are not secrets.
NOISE_SUFFIXES = (".min.js", ".min.css", ".map", ".svg", ".lock", ".sum")
NOISE_NAMES = frozenset(
	{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock",
	 "cargo.lock", "gemfile.lock", "podfile.lock", "go.sum", "npm-shrinkwrap.json"}
)


def should_skip_file(file_path: str) -> bool:
	"""True for binary and generated files that text scanners should not read."""
	path = PurePosixPath(file_path.replace("\\", "/"))
	name = path.name.lower()
	return (
		path.suffix.lower() in BINARY_EXTENSIONS
		or name in NOISE_NAMES
		or name.endswith(NOISE_SUFFIXES)
	)


def looks_binary(data: bytes | str) -> bool:
	"""True when the first chunk contains NUL bytes or many undecodable characters."""
	if isinstance(data, str):
		head = data[:8192]
		return "\x00" in head or head.count("�") > 8
	head = data[:8192]
	return b"\x00" in head
