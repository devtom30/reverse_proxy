docker run --name dropofculture-valkey \
-v /home/tom/RustroverProjects/reverse-proxy/data:/data \
-p 6379:6379 \
-d valkey/valkey \
valkey-server \
--save 60 1 --loglevel warning
