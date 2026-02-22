.PHONY: db-create db-gen-entities

db-create:
	sea-orm-cli migrate up

db-gen-entities:
	sea-orm-cli generate entity -u sqlite://data.db -o src/entities