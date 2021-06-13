DOCKER_MANIFEST=DOCKER_CLI_EXPERIMENTAL=enabled docker manifest

docker-login-ci:
	docker login -u "$$DOCKER_USER" -p "$$DOCKER_PASS";

docker-manifest-annotate:
	echo ${VERSION}
	${DOCKER_MANIFEST} create --amend "floriansdev/screego-dev:unstable"     "floriansdev/screego-dev:amd64-unstable"     "floriansdev/screego-dev:386-unstable"     "floriansdev/screego-dev:armv7-unstable"     "floriansdev/screego-dev:arm64-unstable"     "floriansdev/screego-dev:ppc64le-unstable"
	${DOCKER_MANIFEST} create --amend "floriansdev/screego-dev:${VERSION}" "floriansdev/screego-dev:amd64-${VERSION}" "floriansdev/screego-dev:386-${VERSION}" "floriansdev/screego-dev:armv7-${VERSION}" "floriansdev/screego-dev:arm64-${VERSION}" "floriansdev/screego-dev:ppc64le-${VERSION}"
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:unstable"     "floriansdev/screego-dev:amd64-unstable"       --os=linux --arch=amd64
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:${VERSION}" "floriansdev/screego-dev:amd64-${VERSION}"   --os=linux --arch=amd64
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:unstable"     "floriansdev/screego-dev:386-unstable"         --os=linux --arch=386
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:${VERSION}" "floriansdev/screego-dev:386-${VERSION}"     --os=linux --arch=386
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:unstable"     "floriansdev/screego-dev:armv7-unstable"       --os=linux --arch=arm --variant=v7
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:${VERSION}" "floriansdev/screego-dev:armv7-${VERSION}"   --os=linux --arch=arm --variant=v7
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:unstable"     "floriansdev/screego-dev:arm64-unstable"       --os=linux --arch=arm64
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:${VERSION}" "floriansdev/screego-dev:arm64-${VERSION}"   --os=linux --arch=arm64
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:unstable"     "floriansdev/screego-dev:ppc64le-unstable"     --os=linux --arch=ppc64le
	${DOCKER_MANIFEST} annotate "floriansdev/screego-dev:${VERSION}" "floriansdev/screego-dev:ppc64le-${VERSION}" --os=linux --arch=ppc64le


docker-manifest-push:
	${DOCKER_MANIFEST} push "floriansdev/screego-dev:${VERSION}"
	${DOCKER_MANIFEST} push "floriansdev/screego-dev:unstable"

