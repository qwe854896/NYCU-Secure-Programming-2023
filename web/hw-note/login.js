fetch("/login",{method:"POST",body:`username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,headers:{"Content-Type":"application/x-www-form-urlencoded"}});
