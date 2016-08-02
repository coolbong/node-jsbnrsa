/**
 * Created by haksookim on 2016-08-02.
 */

var assert = require('assert');
var BigInteger = require('../index').BigInteger;

exports.bigInteger = {

    'big integer 1': function() {
        var x = new BigInteger("abcd1234", 16);
        var y = new BigInteger("beef", 16);
        var z = x.mod(y);
        assert('B60C' === z.toString(16).toUpperCase());
    },
    'big integer 2' : function() {
        //example : https://github.com/131/jsbn
        var a = new BigInteger('91823918239182398123');
        assert(67 === a.bitLength());
    }
};