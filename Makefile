.PHONY: help update create_user alias reset_password make_script_executable run_script learn_spam learn_ham unlearn_spam unlearn_ham

help:
	@echo "Usage:"
	@echo " make update                                  # Update and upgrade the system"
	@echo " make create_user USER= DOMAIN= PASSWORD=     # Create a new virtual email user"
	@echo " make alias ALIAS= REAL_EMAIL=                # Create an alias for an existing email"
	@echo " make reset_password USER= DOMAIN= PASSWORD=  # Reset password for a virtual email user"
	@echo " make make_script_executable                  # Make the setup script executable"
	@echo " make run_script DOMAIN=                              # Run the setup script with sudo privileges"
	@echo " make learn_spam PATH=                        # Teach SpamAssassin about spam emails"
	@echo " make learn_ham PATH=                         # Teach SpamAssassin about ham emails"
	@echo " make unlearn_spam PATH=                      # Unteach SpamAssassin about spam emails"
	@echo " make unlearn_ham PATH=                       # Unteach SpamAssassin about ham emails"

update:
	sudo apt update && sudo apt upgrade -y

create_user:
	@echo "Creating new virtual email user $(USER)@$(DOMAIN)"
	sudo mysql -u postfix -p"$$MYSQL_POSTFIX_PASSWORD" -e "INSERT INTO postfix.virtual_users (email, password) VALUES ('$(USER)@$(DOMAIN)', ENCRYPT('$(PASSWORD)'));"

alias:
	@echo "Creating alias $(ALIAS) for $(REAL_EMAIL)"
	sudo bash -c "echo '$(ALIAS): $(REAL_EMAIL)' >> /etc/postfix/virtual"
	sudo postmap /etc/postfix/virtual
	sudo systemctl reload postfix

reset_password:
	@echo "Resetting password for user $(USER)@$(DOMAIN)"
	sudo mysql -u postfix -p"$$MYSQL_POSTFIX_PASSWORD" -e "UPDATE postfix.virtual_users SET password=ENCRYPT('$(PASSWORD)') WHERE email='$(USER)@$(DOMAIN)';"

make_script_executable:
	@echo "Making the setup script executable"
	chmod +x setup_email_server.sh

run_script: make_script_executable
	@echo "Running the setup script with sudo privileges"
	DOMAIN=$(DOMAIN) sudo -E MYSQL_ROOT_PASSWORD=$$MYSQL_ROOT_PASSWORD MYSQL_POSTFIX_PASSWORD=$$MYSQL_POSTFIX_PASSWORD ./setup_email_server.sh $(DOMAIN)

learn_spam:
	@echo "Learning spam from $(PATH)"
	sudo sa-learn --spam $(PATH) --progress

learn_ham:
	@echo "Learning ham from $(PATH)"
	sudo sa-learn --ham $(PATH) --progress

unlearn_spam:
	@echo "Unlearning spam from $(PATH)"
	sudo sa-learn --forget $(PATH) --progress

unlearn_ham:
	@echo "Unlearning ham from $(PATH)"
	sudo sa-learn --forget $(PATH) --progress
