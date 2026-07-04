from stem import Signal
from stem.control import Controller
from config import TOR_CONTROL_PORT, TOR_PASSWORD


def renew_tor_circuit():
    with Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:
        ctrl.authenticate(password=TOR_PASSWORD)
        ctrl.signal(Signal.NEWNYM)
