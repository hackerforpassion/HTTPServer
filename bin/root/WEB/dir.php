<?php
if(!($DIRECTORY))
{
	$dir_open = opendir('.');
}
else
{
	$dir_open = opendir($DIRECTORY);
}

while(false !== ($filename = readdir($dir_open))){
    if($filename != "." && $filename != ".."){
        $link = "<a href='./$filename'> $DIRECTORY.$filename </a><br />";
        echo $link;
    }
}

closedir($dir_open);
?>

