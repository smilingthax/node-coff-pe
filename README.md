PE file format
==============

Read Windows EXE/DLL/... files with NodeJS.

Usage:
```js
var fs = require('fs');
var pe = require('node-coff-pe');

var fd = fs.openSync('./some.exe', 'r');
pe.read(fd, function(err, exehdr, coffhdr) {
  if (err) throw err;
  console.log(exehdr);
  console.log(coffhdr);
  pe.getSection(fd, coffhdr, '.rsrc', function(err, data) {
    if (err) throw err;
    console.log(data); // could be null, if section not found
  });
  pe.checksum(fd, coffhdr, function(err, checksum) {
    if (err) throw err;
    console.log('Checksum:', checksum.toString(16));
    console.log('Expected:', coffhdr.Optional.Checksum.toString(16));
  });
});
```

TODO: Update, Write.

Copyright (c) 2016 Tobias Hoffmann

License: http://opensource.org/licenses/MIT

