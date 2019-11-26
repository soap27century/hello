echo 'Power off network for repairs'
pnetworking off

echo 'Adding test network infrastructure'
pnetworking add test-switch unreliable_switch
pnetworking add test-nic vnic 1.2.3.4

echo 'Hooking up test network'
pnetworking config test-nic connect test-switch
pnetworking config test-nic route add default

echo 'Powering up test network'
pnetworking on > /dev/null 2>&1

echo 'Installing connector of interest'
cp -r ../crap ~/.playground/connectors/
cp -r ../poop ~/.playground/connectors/

echo 'Running echo test'
python raw_echotest.py server --stack=crap &
SERVER_PID=$!
python raw_echotest.py 1.2.3.4 --stack=crap

echo 'Clean up test network'
pnetworking remove test-nic
pnetworking remove test-switch
kill $SERVER_PID
