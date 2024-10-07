protoc -I=protobuf --python_out=tesla_bluetooth/pb2 protobuf/*.proto
protol --create-package --in-place --python-out tesla_bluetooth/pb2 \
  protoc --proto-path=protobuf *.proto
