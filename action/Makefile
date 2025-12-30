ESBUILD_ARGS := --bundle --packages=bundle --platform=node --sourcemap --target=node20 --outdir=dist

.PHONY: bootstrap
bootstrap:
	npm install

.PHONY: build
build:
	npx esbuild src/main.ts $(ESBUILD_ARGS)
	npx esbuild src/post.ts $(ESBUILD_ARGS)

.PHONY: fix
fix:
	npx eslint --fix .

.PHONY: test.artifacts
test.artifacts:
	git diff --exit-code --quiet dist || (echo "dist has changed, please commit the changes" && exit 1)

.PHONY: test.lint
test.lint:
	npx eslint .

.PHONY: test.types
test.types:
	npx tsc --noEmit

.PHONY: test.unit
test.unit:
	npm test
