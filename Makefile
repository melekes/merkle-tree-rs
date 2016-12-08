.PHONY: create_dev_env run_shell

LIB_NAME = merkle_tree

create_dev_env:
		docker build -t $(LIB_NAME) .

run_shell:
		docker run -it --rm -v "$(PWD)":/usr/src/lib $(LIB_NAME) /bin/bash
