
var fs = require('fs');

// baseline implementation
// will not ensure WORD alignment, will not handle a single trailing byte
// will not do the final folding, but allows input sums >0xffff (but < 2^31)
function chksum(sum, buf) {
  // assert(sum < (1<<31));
  for (var i=0, len=buf.length; i<len; i+=2) {
    sum += buf.readUInt16LE(i, true);
    sum = (sum&0xffff) + (sum>>16);
  }
  return sum;
//  return (sum + (sum>>16))&0xffff; // only at the very end
}

// cb(err, checksum)
module.exports = function(fd, coffhdr, cb) {
  if ( (!coffhdr)||(coffhdr._fileOffsets.optionalStart+0x40+4 > coffhdr._fileOffsets.sectionStart) ) {
    cb(new Error('bad invocation'));
    return;
  }

  var checksumOffset = coffhdr._fileOffsets.optionalStart+0x40;
  var checksum = 0;
  var size = 0; // ReadStream.bytesRead only in node >= 6.4.0
  var leftover = null;

  fs.createReadStream(null, {
    fd: fd,
    autoClose: false
  }).on('error', function(err) {
    cb(err);
  }).on('end', function() {
    if (leftover !== null) {
      checksum += leftover;
    }
    checksum = (checksum + (checksum>>16))&0xffff;
    cb(null, checksum + size);
  }).on('data', function(data) {
    if (!data.length) {
      return;
    }

    // set checksum field to 0
    // NOTE: we can't just "unchecksum", because chksum(0xffff,0xffff) = chksum(0x0,0xffff)
    if ( (size < checksumOffset+4)&&(size+data.length > checksumOffset) ) {
      var pos = checksumOffset - size; // -4 < pos < data.length
      var end = Math.min(pos+4, data.length);
      for (pos=Math.max(0,pos); pos<end; pos++) {
        data[pos] = 0;
      }
    }

    size += data.length; // before .slice!
    if (leftover !== null) {
      checksum += leftover + (data.readUInt8(0, true) << 8);
      leftover = null;
      data = data.slice(1);
    }
    checksum = chksum(checksum, data);
    if (data.length & 1) {
      leftover = data.readUInt8(data.length-1, true);
    }
  });
};

