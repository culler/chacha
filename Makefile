.PHONY: usage clean dist testpypi-upload pypi-upload

usage:
	@echo Available make targets are: \
	clean, dist, testpypi-upload, and pypi-upload	

dist:
# Unset PIP_CONFIG_FILE in case pip.conf sets user = True
	env PIP_CONFIG_FILE=/dev/null python3 -m build --sdist --wheel .

clean:
	rm -rf build dist */*.egg-info
	rm -rf `find . -name __pycache__`
	rm -f src/_chacha/_chacha.c

testpypi-upload:
	python3 -m twine upload --verbose --repository testpypi dist/*

pypi-upload:
	python3 -m twine upload dist/*
