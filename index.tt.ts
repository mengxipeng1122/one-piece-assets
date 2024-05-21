import {createHash} from 'crypto'
import {decode} from 'iconv-lite'
const test = ()=>{

    
    const input = Buffer.from([0xC4, 0xE3, 0xBA, 0xC3, 0xA4]); // UTF-8 encoded string "Ößä"
    const decodedString = decode(input, 'utf8');
    console.log('decodedString', decodedString);
}

console.log('##################################################')
test();
