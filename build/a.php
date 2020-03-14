<?php

$f = fopen("sign.txt","r");

$contain = fread($f, filesize("sign.txt"));
echo base64_encode($contain);
