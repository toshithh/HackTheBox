from ctypes import CDLL
import datetime

## Implement C random in Python3 ->
# https://gist.github.com/SakiiR/a073f22c3943a530a2574dd7fde13e38
## Since the Python3 random library is implemented in a different way than the C one ->
# https://stackoverflow.com/questions/47114939/python-randomint-should-be-equal-to-c-rand
libc = CDLL("libc.so.6")

## Get timestamp from UTC in Unix Epoch
# tzinfo=datetime.timezone(datetime.timedelta(0)) -> used to specify UTC
seconds = datetime.datetime(2024, 8, 30, 14, 40, 42,
                             tzinfo=datetime.timezone(datetime.timedelta(0))).timestamp()

for i in range(0, 1000):
    password = ""
    microseconds = i
    current_seed_value = int(seconds * 1000 + microseconds)

    print(current_seed_value)
    ## Set seed of random from libc library
    libc.srand(current_seed_value)
    for j in range(0, 20):
        ## Call random function from libc
        rand_int = libc.rand()
        password += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand_int % 62]

    print(password)
