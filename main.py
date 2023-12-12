#!/usr/bin/env python3

import sys
from crawler import *

if __name__ == "__main__":
    if (len(sys.argv) != 1):
        crawler = Crawler(sys.argv[1])
    else:
        crawler = Crawler()
    crawler.Run()