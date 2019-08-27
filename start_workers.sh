#!/bin/bash

for i in {10100..10150}
do
        taintinduce/taintinduce_worker.py 0.0.0.0 $i &
done

