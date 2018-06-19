import argparse
import docker
import sys
import os
import time


# free the container
def free_container(name, client):
    i = -1
    while(True):
        try:
            i += 1
            container = client.containers.get(name+str(i))
            container.stop()
            container.remove()
            print('free '+name+str(i)+' succeed')
        except docker.errors.NotFound:
            if(i >= 10):
                break

# free the dir


def free_dir(dir):
    list = os.listdir(dir)
    print('remove the files in '+dir)
    for name in list:
        print(name)
        os.removedirs(os.path.join(dir, name))
    if(not os.path.exists(dir)):
        os.mkdir(dir, 0755)


parser = argparse.ArgumentParser()
parser.add_argument('--mode', help='the run or the free',
                    type=str, default='run')
parser.add_argument('--enable_mongodb',
                    help='run the mongodb or not', type=bool, default=False)
parser.add_argument('--producer_number',
                    help='the number of the producer', type=int, default=1)
parser.add_argument(
    '--nodes_number', help='the number of nodes we run', type=int, default=1)
parser.add_argument('--evtd_port_http',
                    help='the begin port of nodes port,port+1 ....', type=int, default=8888)
parser.add_argument(
    '--evtd_port_p2p', help='the begin port of nodes port,port+1 ....', type=int, default=10000)
parser.add_argument(
    '--mongo_db_port', help='the begin port of mongodb port,port+1 ....', type=int, default=27017)
parser.add_argument('--evtd_dir', help='the data directory of the evtd',
                    type=str, default='/home/harry/evtd_data')
parser.add_argument('--mongo_db_dir', help='the data directory of the mongodb',
                    type=str, default='/home/harry/mongo_db_data')
parser.add_argument(
    '--free_dir', help='delete the directory of the mongodb and evtd', type=bool, default=False)
parser = parser.parse_args()


# get the client
client = docker.from_env()

if(parser.mode == 'run'):
    print('check and free the container before')
    free_container('evtd_', client)
    free_container('mongodb_', client)
    # network=client.networks.create("evt-net",driver="bridge")
    # begin the nodes one by one
    if(parser.enable_mongodb):
        print('begin open the mongodb')
        for i in range(0, parser.nodes_number):

            # create files in mongo_db_dir
            if(not os.path.exists(parser.mongo_db_dir)):
                os.mkdir(parser.mongo_db_dir, 0755)
            file = os.path.join(parser.mongo_db_dir, 'dir_'+str(i))
            if(os.path.exists(file)):
                print("Warning: the file before didn't freed ")
            else:
                os.mkdir(file, 0755)

            # make the command
            command = 'mongod --port '+str(parser.mongo_db_port+i)

            # run image mongo in container
            container = client.containers.run(image='mongo:latest',
                                              command=command,
                                              name='mongodb_'+str(i),
                                              network='evt-net',
                                              hostname='127.0.0.1',
                                              ports={
                                                  str(parser.mongo_db_port+i): 27017+i},
                                              detach=True,
                                              volumes={
                                                  file: {'bind': '/data/dbd', 'mode': 'rw'}}
                                              )
        time.sleep(5)

    print('begin open the evtd')
    for i in range(0, parser.nodes_number):

        # create files in evtd_dir
        if(not os.path.exists(parser.evtd_dir)):
            os.mkdir(parser.evtd_dir, 0755)
        file = os.path.join(parser.evtd_dir, 'dir_'+str(i))
        if(os.path.exists(file)):
            print("Warning: the file before didn't freed ")
        else:
            os.mkdir(file, 0755)

        # make the command
        command = 'evtd.sh --delete-all-blocks'
        if(parser.enable_mongodb):
            command += ' --plugin=evt::mongo_db_plugin --mongodb-uri=mongodb://' + \
                'mongodb_'+str(i)+':'+str(27017+i)
        if(i < parser.producer_number):
            command += ' --enable-stale-production --producer-name=evt'
        else:
            command += ' --producer-name=evt.'+str(i)
        command += ' --http-server-address=evtd_'+str(i)+':'+str(8888+i)
        command += ' --p2p-listen-endpoint=evtd_'+str(i)+':'+str(9876+i)
        for j in range(0, parser.nodes_number):
            if(i == j):
                continue
            command += (' --p2p-peer-address=evtd_'+str(j)+':'+str(9876+j))

        # run the image evtd in container
        container = client.containers.run(image='everitoken/evt:latest',
                                          name='evtd_'+str(i),
                                          command=command,
                                          network='evt-net',
                                          ports={
                                              str(parser.evtd_port_http+i): 8888+i, str(parser.evtd_port_p2p+i)+'/tcp': 9876+i},
                                          detach=True,
                                          volumes={
                                              file: {'bind': '/opt/evtd/data', 'mode': 'rw'}}
                                          )

if(parser.mode == 'free'):
    print('free the container')
    free_container('evtd_', client)
    free_container('mongodb_', client)
    if(parser.free_dir):
        free_dir(parser.mongo_db_dir)
        free_dir(parser.evtd_dir)
