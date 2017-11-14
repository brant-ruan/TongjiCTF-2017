//init
var system  = require('system');
var args    = system.args;
var webPage = require('webpage');
var page    = webPage.create();

if (args.length !== 2) {
    console.log('Usage: phantomjs ' + args[0] + ' url');
    phantom.exit(0);
}

function get_domain(url){  
    var durl = /http:\/\/([^\/]+)\//i;  
    domain = url.match(durl);  
    return domain[1];  
}  

//cfg
var url     = args[1];//'http://xbj110825.cn/xss.html';
//var domain  = get_domain(url);//'xbj110825.cn';
var domain  = "127.0.0.1";//'xbj110825.cn';

//add cookie
var flag_cookie = {
    'name'     : 'flag',
    'value'    : 'tj{SCript_in_go_fCr0SSSite}',
    'path'     : '/',
    'domain'   : domain,
    'expires'  : (new Date()).getTime() + (1000 * 60 * 60)
};

if (phantom.addCookie(flag_cookie) == false) {
    console.log('addCookie failed');
    //phantom.exit(-1);
} else {
    console.log('addCookie success');
}

//open
page.open(url, function(status) {});

setTimeout('phantom.exit(0)', 5000)

//debug
page.onPageCreated = function(newPage) {
  console.log('onPageCreated');
  newPage.onClosing = function(closingPage) {
    console.log('newPage.onClosing');
    phantom.exit();
  };
};

page.onLoadFinished = function(status) {
  console.log('onLoadFinished Status:' + status);
};

