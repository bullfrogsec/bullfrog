ESBUILD_ARGS := --bundle --platform=node --sourcemap --target=node20 --outdir=dist

.PHONY: bootstrap
bootstrap:
	npm install

.PHONY: build
build:
	npx esbuild src/main.ts $(ESBUILD_ARGS)
	npx esbuild src/post.ts $(ESBUILD_ARGS)

# Example how to run post. I'm not sure how you ran it locally
.PHONY: post.run
post.run:
	NODE_OPTIONS=--enable-source-maps npx node dist/post.js
