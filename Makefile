.SILENT:

clean:
	rm -rf orbitdb
	rm -rf package-lock.json
	rm -rf node_modules

deps:
	npm install

docs:
	jsdoc README.md src/*.js index.js -d docs -c .jsdoc.config.js

lint:
	npx standard

quicktest:
	npx mocha

test: lint deps
	npx mocha

build: lint deps docs test
	rm -rf dist
	npx webpack --config conf/webpack.config.js
	cp dist/* examples

watch: deps
	npx nodemon --watch index.js --watch README.md --watch src --watch test \
		--exec "rm -rf docs && make docs && make lint && make quicktest"

rebuild: clean build
