import sys
import argparse
from pprint import PrettyPrinter

pp = PrettyPrinter(indent=4)

class MyParser(argparse.ArgumentParser):
    """Custom argparser error message."""

    def error(self, message):
        sys.stderr.write('\n*** error: %s\n\n' % message)
        self.print_help()
        sys.exit(2)
