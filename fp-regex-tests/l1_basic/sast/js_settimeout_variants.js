function tick() { console.log('heartbeat'); }
setTimeout("tick()", 1000);
setTimeout(() => tick(), 1000);
