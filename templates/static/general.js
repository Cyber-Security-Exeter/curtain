function get_cookies() {
  const cookies_string = document.cookie;
  const cookies = cookies_string.split(";");
  let cookies_dict = {};
  cookies.forEach((cookie) => {
    const split = cookie.split("=");
    cookies_dict[split[0]] = split[1];
  });
  return cookies_dict;
}

function form_data_to_object(data) {
  const obj = {};
  data.forEach((value, key) => {
    if (obj.hasOwnProperty(key)) {
      if (!Array.isArray(obj[key])) {
        obj[key] = [obj[key]];
      }
      obj[key].push(value);
    } else {
      obj[key] = value;
    }
  });
  return obj;
}

async function check_valid_jwt(jwt) {
  let isvalid = false;
  await fetch("/api/check_valid_jwt", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: '{"jwt": "' + jwt + '"}',
  })
    .then((response) => response.json())
    .then((data) => {
      let jsondata = JSON.parse(data);
      if (jsondata["status"] != "ok") {
        isvalid = false;
      } else {
        isvalid = true;
      }
    })
    .catch((error) => {
      isvalid = false;
    });
  return isvalid;
}

let jwt = "";
if (
  get_cookies().hasOwnProperty("super_secret_dont_touch") ||
  sessionStorage.getItem("super_secret_dont_touch") != null
) {
  if (get_cookies().hasOwnProperty("super_secret_dont_touch")) {
    jwt = get_cookies()["super_secret_dont_touch"];
  } else {
    jwt = sessionStorage.getItem("super_secret_dont_touch");
  }
}
check_valid_jwt(jwt).then((isvalid) => {
  if (!isvalid) {
    jwt = "";
  }
  console.log(jwt);
  if (
    window.location.pathname == "/" ||
    window.location.pathname == "/register"
  ) {
    if (jwt != "") {
      window.location.replace("/home");
    }
  }

  if (
    window.location.pathname != "/" &&
    window.location.pathname != "/register"
  ) {
    if (jwt == "") {
      window.location.replace("/");
    }
  }
});

function includeHTML() {

    // https://www.w3schools.com/howto/howto_html_include.asp
    var z, i, elmnt, file, xhttp;
    /* Loop through a collection of all HTML elements: */
    z = document.getElementsByTagName("*");
    console.log(z);
    for (i = 0; i < z.length; i++) {
        elmnt = z[i];
        /*search for elements with a certain atrribute:*/
        file = elmnt.getAttribute("w3-include-html");
        if (file) {
            /* Make an HTTP request using the attribute value as the file name: */
            xhttp = new XMLHttpRequest();
            xhttp.onreadystatechange = function () {
            if (this.readyState == 4) {
                if (this.status == 200) {
                elmnt.innerHTML = this.responseText;
                }
                if (this.status == 404) {
                elmnt.innerHTML = "Page not found.";
                }
                /* Remove the attribute, and call this function once more: */
                elmnt.removeAttribute("w3-include-html");
                includeHTML();
            }
            };
            xhttp.open("GET", file, true);
            xhttp.send();
            return;
        }
    }
}

window.onload = function () {
    includeHTML()
};
