clean:
	rm -rf \
	__pycache__ \
	src/REPLACEME_PROJECT_NAME/__pycache__ \
	tests/__pycache__ \
	.pytest_cache \
	dist \
	_version.py \
	*.egg-info \
	src/*.egg-info \
	docsrc/_doctrees
	
test:
	pytest
