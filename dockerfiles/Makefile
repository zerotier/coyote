all: zlint

ZLINT=3.3.0

zlint:
	docker build --build-arg ZLINT=${ZLINT} -t zerotier/zlint:latest -f Dockerfile.zlint .
