document.getElementById("lf").addEventListener("submit",async function(e){
  e.preventDefault();
  var msg=document.getElementById("msg");
  var ok=document.getElementById("ok");
  msg.style.display="none";
  ok.style.display="none";
  try{
    var r=await fetch("/api/auth/login",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})
    });
    var d=await r.json();
    if(r.ok&&d.session_id){
      localStorage.setItem("cerberix_token",d.session_id);
      ok.textContent="Login OK! Redirecting...";
      ok.style.display="block";
      setTimeout(function(){window.location.href="/";},500);
    }else{
      msg.textContent=d.error||"Login failed";
      msg.style.display="block";
    }
  }catch(ex){
    msg.textContent="Error: "+ex.message;
    msg.style.display="block";
  }
});
