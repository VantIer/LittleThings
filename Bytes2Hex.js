function Bytes2Hex(arr){
  var str = "";
  for(var i=0; i<arr.length; i++)
  {
     var tmp = arr[i].toString(16);
     if(tmp.length == 1)
     {
         tmp = "0" + tmp;
     }
     str += tmp;
  }
  return str;
}