.PHONY: run clean

# To run the password manager
run:
	python3 password_manager.py

# To install required Python packages
install:
	pip3 install -r requirements.txt

# Clean is not strictly necessary, but provided for uniformity
clean:
	rm -f *.pyc
