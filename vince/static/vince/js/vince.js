/*#########################################################################
  # VINCE
  #
  # Copyright 2023 Carnegie Mellon University.
  #
  # NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
  # INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
  # UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
  # AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  # PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
  # MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
  # WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
  #
  # Released under a MIT (SEI)-style license, please see license.txt or contact
  # permission@sei.cmu.edu for full terms.
  #
  # [DISTRIBUTION STATEMENT A] This material has been approved for public
  # release and unlimited distribution.  Please see Copyright notice for non-US
  # Government use and distribution.
  #
  # Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
  # U.S. Patent and Trademark Office by Carnegie Mellon University.
  #
  # This Software includes and/or makes use of Third-Party Software each subject
  # to its own license.
  #
  # DM21-1126
  ########################################################################
*/

/* Global functions for VINCETrack */

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length +
								  1));
                break;
            }
        }
    }
    return cookieValue;
}
function copyToClipboard(text) {
    var $temp = $("<input>");
    $("body").append($temp);
    $temp.val(text).select();
    document.execCommand("copy");
    $temp.remove();
}
/* Across the board loader functions */
function lockunlock(f,divmain,divhtml) {
    if(f) {
	/* Show search is in progress */
	$(divmain).css({opacity:0.5});
	if($(divhtml).find('.loading').length < 1)
	    $(divhtml).prepend($('#hiddenloading').html());
    } else {
	/* Back to normal */
	$(divmain).css({opacity:1});
	$(divhtml).find('.loading').remove();
    }
}
function delaySearch(callfun,wait) {
    var timeout;
    return (...args) => {
        clearTimeout(timeout);
        timeout = setTimeout(
	    function () {
                callfun.apply(this, args);
	    }, wait);
    };
}
function deepGet(obj,idir) {
    let x= obj;
    let y = idir.split(".");
    y.every(function(d) { 
	if (typeof(x) == "object" && d in x) {
	    x = x[d];
	    return true;
	} else {
	    x = null;
	    return false;
	}});
    return x;
}


function asyncLoad(fdiv,furl,fmethod,pdiv,formpost,silent,transform) {
    /* asyncload from furl(URL) to fdiv(Content div identifier) whose
       pdiv(Parent div identified) using fmethod(GET or POST)
       in the case of POST use the formpost(Form identified) that
       should be serialized. The var silent is now suppressed.
    */
    if(!furl)
	furl = fdiv.getAttribute("href");
    if(!furl) {
	console.log("This div is not valid for async load return");
	return;
    }
    if(!fmethod) {
	if(fdiv.getAttribute("method"))
	    fmethod = fdiv.getAttribute("method")
	else
	    fmethod = "GET";
    }
    if(!pdiv) {
	if(fdiv.getAttribute("parentdiv"))
	    pdiv = fdiv.getAttribute("parentdiv");
	else
	    pdiv = fdiv;
    }
    let fdata = null;
    if(fmethod == "POST") {
	if (!formpost) {
	    if(fdiv.getAttribute("form"))
		formpost = fdiv.getAttribute("form");
	}
	if($(formpost).serialize())
	    fdata = $(formpost).serialize();
    }
    lockunlock(true,pdiv,fdiv);
	console.log('furl is ')
	console.log(furl)
	console.log('fmethod is ')
	console.log(fmethod)
	console.log('fdata is ')
	console.log(fdata)
    window.txhr = $.ajax({
        url : furl,
        type: fmethod,
        data: fdata,
        success: function(data) {
	    	lockunlock(false,pdiv,fdiv);
	    	if(transform && typeof(transform) == 'function')
				$(fdiv).html(transform(data)).foundation();
	    	else
				$(fdiv).html(data).foundation();
			console.log($(fdiv))
        	},
		error: function() {
		    lockunlock(false,pdiv,fdiv);
		    console.log(arguments);
	    	/* The var silent is no longer being used */
	    	$(fdiv).html("Content failed to be collected for display! "+
			 "See console log for details.");
		},
		complete: function() {
	    	/* Just safety net */
		    lockunlock(false,pdiv,fdiv);
		    window.txhr = null;
		}
    });
}

function clickAsyncLoad(e) {
    /* Async loader for buttons will use data attributes
       data-qparams="all=true" data-divid="ticket_activity"
    */
    let el = e.target;
    if($(el).data("divid")) {
        let fdiv = document.getElementById($(el).data("divid"));
        let pdiv = fdiv;
        if(fdiv.getAttribute('href')) {
	    let furl = fdiv.getAttribute('href');
	    if($(el).attr("data-completeurl") == furl) {
		console.log("Already loaded content as per URL return");
		return true;
	    }
	    let fmethod = "GET"
	    if ($(el).data("qparams"))
                furl = furl + "?" + $(el).data("qparams");
	    if($(el).data("method"))
                fmethod = $(el).data("method");
	    if($(el).data("parentdiv"))
                pdiv = $(el).data("parentdiv");
	    let formpost = null;
	    if($(el).data("form"))
                formpost = $(el).data("form");
	    let transform = null;
	    if($(el).data("transform") && $(el).data("transform") in window
	       && typeof(window[$(el).data("transform")]) == "function")
		transform = window[$(el).data("transform")];
	    asyncLoad(fdiv,furl,fmethod,pdiv,formpost,true,transform);
	    /* Mark download as complete */
	    $(el).attr("data-completeurl",furl);
        }
    }
}
function pageAsyncLoad(e) {
    /* Async loader for buttons will use closest div.asyncload */
    let el = e.target;
    let page = parseInt($(el).attr('next'));
    if(isNaN(page)) {
	console.log(el);
	console.log("Invalid page number returning " + $(el).attr('next'));
	return;
    }
    let jfdiv = $(el).closest('div.asyncload');
    if(jfdiv.length == 1 && page) {
	let fdiv = jfdiv[0];
	let furl = fdiv.getAttribute('href');
	let fmethod = fdiv.getAttribute('method');
	if(fmethod == 'POST') {
	    if(fdiv.getAttribute("form")) {
		let formpost = fdiv.getAttribute("form");
		$(formpost).find('input[name="page"]').val(page);
	    }
	} else {
	    furl = furl + "?page=" + String(page);
	}
	asyncLoad(fdiv,furl,fmethod);
    }
}

function get_modal() {
    let hm = $('#txmodal');
    if(hm.length != 1) {
	$('body').append($('<div>').addClass("reveal").
			 attr({"id": "xmodal",
			       "role": "dialog",
			       "aria-hidden": "true",
			       "data-close-on-click": "false",
			       "data-close-on-esc": "false",
			       "data-yeti": "modal",
			       "data-resize": "modal"}).
			 css({"border": "2px solid #007dac",
			      "border-radius": "12px"}));
        let _ = new Foundation.Reveal($('#xmodal'));
        _.open();
	$('#xmodal').append($('<div>').attr({"id": "txmodal"}).
			    css({"padding": "12px"}))
        hm = $('#txmodal');
    }
    hm.html("<button class='button small primary tempbutton showli' " +
	    " style='display:none'>" +
	    "Show All Results</button>&nbsp; &nbsp;");
    hm.append("<button class='close-button tempbutton closem'" +
	      " style='display:none'> X </button>")
    hm.find('.showli').on('click', function() {
	$('#txmodal li').show();
    });
    hm.find('.closem').on('click', function() {
	$('#xmodal').foundation('close');
    });    
    $('#xmodal').foundation('open');
    return hm;
}
function finish_modal(hm) {
    hm.find('.tempbutton').show();
    hm.append("<p>Operation complete, you may close this window</p>");
}

function checkemail(vemails) { 
	let emails = vemails.split(",");
	let remail = /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/;
	for(let i = 0; i < emails.length; i++) {
		if(!remail.test(emails[i])) {
			alert("Email entry " + emails[i] + " is invalid! \n" + "Enter valid email address before submitting.");
			return false;
		}
	}
	return true;
	}

$(function () {

    /*$('span[title]').qtip({
      style: {classes: 'qtip-youtube'}
      });*/
    /*
      $('span').tooltip({
      tooltipClass: 'tooltipster-default'
      });
      
      $('i').tooltip({
      tooltipClass: 'tooltipster-default'
      });

      $('button').tooltip({
      tooltipClass: 'tooltipster-default'
      });
    */

	// The following 70 lines or so is a rough draft that needs substantial work for getting parts of the case & ticket pages to refresh automatically.

	// let periodBetweenInactivityChecks = 10000;
	// let autorefreshInterval = 60000;
	// let time = new Date().getTime();
	
	// $(document.body).bind("mousemove keypress", function(e) {
	// 	time = new Date().getTime();
	// });
	
	// function autorefresh() {
	// 	console.log('autorefresh is starting')
    //     let request = new XMLHttpRequest();
    //     request.open('GET', location.href.replace(location.hash,""));
    //     request.onload = function () {
    //         if (request.response){
    //             let retrievedHTML = request.response;
    //             const parser = new DOMParser();
    //             const parsedHTML = parser.parseFromString(retrievedHTML, "text/html");
    //             $('.shouldautorefresh').each(function() {
    //                 current_id = $(this).attr("id");
    //                 html_to_inject = parsedHTML.querySelectorAll("[id='"+current_id+"']")[0].innerHTML
    //                 if ($(this).html() != html_to_inject) {
    //                     console.log('we are replacing the html')
    //                     $(this).html(html_to_inject)
    //                 }
    //             });
    //         }
    //     };
    //     request.send();



		// The below code is for if we want to prevent refreshing the page when there is content in the comment box.

		// inputText = document.getElementById("commentBox").value;
		// if (inputText == "") {
		// 	console.log('inputText is empty')
		// 	if (new Date().getTime() - time >= autorefreshInterval) {
		// 		location.reload(true);
		// 	} else {
		// 		setTimeout(autorefresh, periodBetweenInactivityChecks);
		// 	}
		// }

	// }
	
	// if ($('.shouldautorefresh')[0]){
	// 	setTimeout(autorefresh, autorefreshInterval);
	// }

	// This works like a charm, but the above might be better:

	// let autorefreshInterval = 60000

    // function autorefresh(){
    //     inputText = document.getElementById("commentBox").value
	// 	if (inputText == ''){
	// 		$.get(location.href,function(retrievedHTML) {
	// 			const parser = new DOMParser();
	// 			const parsedHTML = parser.parseFromString(retrievedHTML, "text/html");
	// 			if (!parsedHTML.isEqualNode(document)) {
	// 				location.reload()
	// 			}
	// 		})
	// 	}
    // };

    // if ($('.shouldautorefresh')[0]){
    //     setInterval(autorefresh, autorefreshInterval);
    // }
	  
	var tabIDsoughtviaurl = $(location).prop('hash').substr(1);
	
	if (tabIDsoughtviaurl){
		let divtoload = document.getElementById(tabIDsoughtviaurl);
		if (divtoload && divtoload.classList.contains("asynchronized")){
			divtoload.classList.add("asyncload","autoload");
		};
	};

    $('[vince-tooltip]').tooltip ({
	tooltipClass: 'vince-tooltip-class',
	content: function() {
	    var element = $( this );
	    return element.attr("href").toString();
	    
	},
    });

    $('[vince-tooltip]').on('copy', function(event) {
	event.preventDefault();
	copyToClipboard($(this).attr("href"));
    })

    var prev = 0;
    var $window = $(window);
    var nav = $('ul.vincesidemenu');
    
    $window.on('scroll', function(){
	var scrollTop = $window.scrollTop();
	nav.toggleClass('less_padding', scrollTop > prev);
	prev = scrollTop;
    });

    /* scroll button */

    $(window).scroll(function () {
        if ($(this).scrollTop() > 100) {
            $('.scrollup').fadeIn();
        } else {
            $('.scrollup').fadeOut();
        }
    });
    $('.scrollup').click(function () {
        $("html, body").animate({
            scrollTop: 0
        }, 600);
        return false;
    });
    function post_content_refresh(ctx) {
	/* This function runs on all divs that can use SHOW_MORE
	   and SHOW_LESS*/
	if(!ctx) 
	    ctx = document.body;
	var lines = 12; 
	var buttonspacing = 0; 
	var buttonside = 'left'; 
	var animationspeed = 1000;
	var lineheight = 0;
	if ($('.text_content',ctx).css("line-height")) {
	    lineheight = $('.text_content',ctx).css("line-height").
		replace("px", "");
	}
	var startheight = lineheight * lines;
	var shortheight = $('.textheightshort',ctx).css('max-height');
	var buttonheight =  $('.showfull',ctx).height();
	$('div.long_text_container',ctx).css(
	    {'padding-bottom' : (buttonheight + buttonspacing ) });

	if(buttonside == 'right'){
            $('.showfull',ctx).css(
		{'bottom' : (buttonspacing / 2), 'right' : buttonspacing });
	} else{
	    $('.showfull',ctx).css(
		{'bottom' : (buttonspacing / 2), 'left' : buttonspacing });
	}

	$('.moretext',ctx).on('click', function(){
            var newheight = $(this).parent('div.long_text_container').
		find('div.text_content').height();
            $(this).parent('div.long_text_container').
		find('div.text_container').
		animate({'max-height' : newheight }, animationspeed );
            $(this).hide().siblings('.lesstext').show();
            $(this).next().next('.scrollnext').fadeIn();

	});

	$('.lesstext',ctx).on('click', function(){
	    var shortelem = $(this).parent('div.long_text_container').
		find('div.text_container').hasClass('textheightshort');
	    var newheight = startheight;
	    if (shortelem) {
		newheight = shortheight;
	    }
            var h = $(this).parent('div.long_text_container').
		find('div.text_content').height();
            $(this).parent('div.long_text_container').
		find('div.text_container').
		animate({'max-height' : newheight }, animationspeed );
            $(this).hide().siblings('.moretext').show();
            $(this).next('.scrollnext').fadeOut();
	});

	$('div.long_text_container',ctx).each(function(){
	    var elm = $(this).find('div.text_content');
            if( elm.height() > $(this).find('div.text_container').height()){
		$(this).find('.showfull.moretext').show();

            }
	});
    }
    /* Run post_content_refresh once and then on any divs that are
       dynamically generated */
    post_content_refresh();
    function mutation_refresh(mu,ob) {
	console.log(arguments);
	if(mu.length && mu[0].target) {
	    if($(mu[0].target).attr("onmutate")) {
		post_content_refresh(mu[0].target);
	    }
	}
    }
    $('.asyncrefresh').each(function() {
	console.log(arguments);
	let ob = new MutationObserver(mutation_refresh);
	ob.observe(this,{childList:true});
    });
    $(document).keyup(function(e) {
        if (e.key === "Escape") {
            if(window.txhr && 'abort' in window.txhr) {
		console.log("Aborting search because user hit Escape");
		window.txhr.abort();
		window.txhr = null;
            }
        }
    });
    /* All asyncload class div with autoload should be populated async on
       document.ready()  */
    $('div.asyncload.autoload').each(function(_,fdiv) {
	asyncLoad(fdiv);
    });
    /* Create async onclick loaders via buttons if any */
    $('.asyncclick').on("click", clickAsyncLoad);
    /* Create async page loaders if any */
    $(document).on("click",".asyncpage",pageAsyncLoad);
    function loadiftarget(formpost,e) {
	$(formpost).find('input[name="page"]').val(1);
	let fdivid = $(formpost).attr("targetdivid")
	if(fdivid && document.getElementById(fdivid)) {
	    e.preventDefault();
	    e.stopPropagation();
	    asyncLoad(document.getElementById(fdivid));
	}
    }
    $('.asyncform').on("submit keyup keypress",function(e) {
	let keyCode = e.keyCode || e.which;
	if (keyCode === 13) {
            e.preventDefault();
	    e.stopPropagation();
            return false;
	}
	loadiftarget(e.target,e);
    });
    $('.asyncdelaysearch').on("keyup keypress", delaySearch(function(e) {
	let keyCode = e.keyCode || e.which;
	if (keyCode === 13) {
            e.preventDefault();
	    e.stopPropagation();
            return false;
	}
	loadiftarget($(e.target).closest('form'),e);
    },1000));
    $('.asyncform input').not('.asyncdelaysearch').on("change",function(e) {
	loadiftarget($(e.target).closest('form'),e);
    });
    $('.select_all_checkbox').on('click',function(e) {
	$(e.target).closest('.select_all_group')
	    .find('input[type="checkbox"]')
	    .prop('checked',$(e.target).prop('checked'));
    });
    function json_pretty(d) {
	return JSON.stringify(d,null,'\t')
    }
    function msg_card(el,msg,level) {
	$(el).html(msg).removeClass().addClass('card-' + level +
					       ' dashboard-nav-card');
	if(level == "bad") {
	    $(el).on('click',function() { $('#xmodal').foundation('close'); })
	}	
    }
    function load_cvedata(cvetype) {
	$('a.cvetab').attr("aria-selected","false");
	$('a.cvetab.'+cvetype).attr("aria-selected","true");
	let cvenew = $('#cve5data').data(cvetype);
	if(cvenew && deepGet(cvenew,'containers.cna')) {
	    $('#cve5data').val(json_pretty(cvenew.containers.cna));
	}
    }
    $('#rejectcve5').on('click', function() {
	if(confirm("Reject this CVE and remove any public reference "+
		   " in the CVE Program?")) {
	    let href = $('#cve5json').attr('href');
	}
	
    });
    $('.cve_status').each(function(_,el) {
	if($(el).data("origin")) {
	    $.getJSON($(el).data("origin")).done(function(d) {
		if(('state' in d) && (d.state != "PUBLISHED"))
		    return;
		if(('dateUpdated' in d) && d.dateUpdated) {
		    try {
			let depoch = Date.parse(d.dateUpdated);
			let dtext = new Date(depoch).toLocaleString();
			$(el).html("<br>&nbsp;")
			    .append($('<span>')
				    .html("PUBLISHED on " + dtext)
				    .addClass("goodtext"));
		    } catch(err) {
			console.log("Ignore error on published data "+err)
		    }
		}
	    });
	}
    });
    $('#publishcve5').on('click',function() {
	let hm = get_modal();
	hm.append("<h4><u>Submit CVE5 JSON To CVE Program</u></h4>");
	hm.append($('<small>')
		  .html("If needed edit and update JSON before submission. " +
			"Use the Tabs to compare CVE data in VINCE and " +
			"in the CVE Services API")); 
	hm.append($('<a>').addClass("dashboard-nav-card hide"));
	hm.append($('<ul>').addClass("tabs hide")
		  .append($('<li>').addClass("tabs-title")
			  .append($('<a>').html("CVE VINCE")
				  .addClass('cvevince cvetab')
				  .attr("aria-selected","true"))
			  .on('click', function(e) {
			      load_cvedata('cvevince');
			  }))
		  .append($('<li>').addClass("tabs-title")
			  .append($('<a>').html("CVE Program")
				  .addClass('cveservices cvetab'))
			  .on('click', function(e) {
                              load_cvedata('cveservices');
                          }
			     ))); 
	hm.append($('<textarea>')
		  .attr({id:"cve5data",
			 autocomplete:"off",
			 autocorrect:"off",
			 autocapitalize:"off",
			 spellcheck: "false"})
		  .css({height: "20em",
			width: "100%",
			border: "1px solid grey"})); 
	let href = $('#cve5json').attr('href');
	let el = hm.find(".dashboard-nav-card");
	if(! href) {
	    msg_card(el,"Missing CVE reference","bad");
	    return;
	}
	$.getJSON(href,function(d) {
	    if(deepGet(d,'containers.cna')) {
		let cvedata = d.containers.cna;
		/* Store full data both local vince version and
		   remote cveservice version 
		*/
		$('#cve5data').val(json_pretty(cvedata))
		    .data("cvevince",d);
		if(deepGet(cvedata,"x_generator.origin")) {
		    $.getJSON(deepGet(cvedata,"x_generator.origin"))
			.done(function(d) {
			    $('#cve5data').data("cveservices",d);
			    hm.find('ul.tabs').removeClass('hide');
			});
		}
		let btnSubmit = $('<button>').addClass('button primary')
		    .html("Publish");
		btnSubmit.on('click',function() {
		    let cve5 = $('#cve5data').val();
		    try {
			let cve5Obj = JSON.parse(cve5);
			if(deepGet(cve5Obj,"containers.cna")) {
			    /* Remove non cna container fields */
			    cve5 = json_pretty(cve5Obj.containers.cna);
			    cve5Obj = JSON.parse(cve5);
			    $('#cve5data').val(cve5);
			}
			["affected.0.product",
			 "affected.0.versions.0.version",
			 "affected.0.vendor",
			 "descriptions.0.lang",
			 "descriptions.0.value",
			 "references.0.url"].forEach(function(x) {
			     if(!deepGet(cve5Obj,x))
				 throw new Error("Element " +
						 x + " is required");
			 });
		    } catch(err) {
			msg_card(el,"CVE data incorrect: " + err,"bad");
			return;
		    }
		    let msg = "This CVE will go fully public immediately! "+
			"\nAre you Sure?";
		    el.addClass('hide');
		    if(confirm(msg))
			$.ajax({'type':"POST",
				'url': href + "submit/",
				'data': $('#cve5data').val(),
				contentType: 'application/json',
				dataType: 'json'})
			.done(function(ret) {
			    let m = [{output: ret},{input:cvedata}];
			    $('#cve5data').val(json_pretty(m));
			    if("error" in ret) {
				msg_card(el,"Error: "+ret.error,"bad");
				$('#cve5data').addClass('is-invalid-input');
			    } else if("message" in ret) {
				msg_card(el,"Result: "+ret.message,"good");
				$('#cve5data').removeClass('is-invalid-input');
				if('updated' in ret) {
				    $('#cve5data')
					.data('cveservices',ret.updated);
				    load_cvedata('cveservices');
				}
				
			    } else {
				/* the card-cr class looks like warning*/
				msg_card(el,"Result: "+ret.message,"cr")
			    }
			});
		});
		let btnCancel = $('<button>').addClass('close-button')
		    .html("X")
		    .on('click',function() {
			$('#xmodal').foundation('close');
		    });
		let l = $('<div>').addClass('row')
		    .append($('<div>').addClass("columns large6 text-right")
			    .append(btnSubmit)
			    .append(btnCancel));
		hm.append(l);
	    }
	});
    });
    function rgba_rand(r,g,b,a) {
	let c = [0,0,0];
	for(let i=0; i<3; i++) {
	    if(arguments[i] && (!isNaN(parseInt(arguments[i]))))
		c[i] = arguments[i]
	    else
		c[i] = parseInt(Math.random()*255)
	}
	a && parseFloat(a) ? c.push(a) : c.push(1);
	return "rgba(" + c.join(",") + ")";
    }
    function json_table(data,tr) {
	/* If variable tr (transform) exists and is valid then transform
	 the data before returning it*/
	let tb = $('<table>').addClass("table");
	for(x in data) {
	    if(tr && x in tr) {
		if(typeof(tr[x]) == "function")
		    data[x] = tr[x](data[x]);
		else
		    continue;
	    }
	    tb.append($("<tr>").append($("<td>").text(x))
		      .append($("<td>").text(data[x])));
	}
	return tb;
    }
    function close_uar(msg,timer) {
	$('#txmodal .modal-body').html(msg);
	$('#txmodal .modal-footer')
	    .html($("<button>").addClass("button secondary")
		  .html("Close")
		  .on("click",function() {
		      $('#xmodal').foundation('close');
		  }));
	if(timer) {
	    /* If timer is 0 never close wait for click to close*/
	    if(timer > 0) 
		setTimeout(function() {
		    $('#xmodal').foundation('close');
		},timer);
	}
	
    }
    function reject_uar() {
	let data = $('#txmodal').data("rec");
	if(!(data)) {
	    return close_uar("Data validation error!",3000);
	}
	if(confirm("This user's request will be rejected!\nAre you sure?")) {
	    let csrf_token = getCookie('csrftoken');
	    let uar_data = $('#userapprove').data();
	    let uar_url = uar_data.href;
	    let status_map = uar_data.status_map;
	    /* Note: This pk is user's contact pk */
	    $.post(uar_url,
		  {pk:data.pk,
		   status:status_map.DENIED,
		   username:data.username,
		   csrfmiddlewaretoken: csrf_token}
		  ).done(function(d) {
		      if(d.length == 1 && d[0].fields.contact == data.pk) {
			  close_uar("User request has been denied and closed!",3000);
			  $('#uar-pk-'+String(data.pk)).remove();
		      } else {
			  close_uar("Sorry there was an error! See console log",0);
			  console.log(d);
		      }
		  }).fail(function() {
		      console.log(arguments);
		      close_uar("Sorry there was an error! See console log",0);
		      
		  });
	}
    }
    function tkt_uar() {
	let rec = $('#txmodal').data("rec");
        if((!rec)) {
            return close_uar("Data validation error!",3000);
        }
	let csrf_token = getCookie('csrftoken');
	let pdata = {queue: "vendor",
		     csrfmiddlewaretoken: csrf_token,
		     title: "Vendor Association Group Admin unavailable",
		     description: rec.justification,
		     submitter_email: rec.username
		    }
	/* GET this from ticket/url data-href*/
	let ticket_url = $('.uar-row').data('newticket-url');
	console.log(pdata);
	$.post(ticket_url,pdata).done(function(x) {
	    if("success" in x) {
		let uar_data = $('#userapprove').data();
		let uar_url = uar_data.href;
		let status_map = uar_data.status_map;
		/* Note: This pk is user's contact pk */
		$.post(uar_url,
		       {pk:rec.pk,
			status:status_map.EXPIRED,
			username:rec.username,
			csrfmiddlewaretoken: csrf_token}		
		      ).always(function() { console.log(arguments); })
		return close_uar("Success! a new ticket created for this request");
	    }
	    console.log(x);
	    return close_uar("Error! Could not create ticket. Error is :"
			     + x.error,3000);
	}).fail(function() {
	    console.log(arguments);
	    close_uar("Error in submission to Ticket. See console.log!",0);
	});
    }
    /* If userapprove element exists display it and create user approve rows*/
    if($('#userapprove').data('href')) {
	let two_weeks = 1209600000;
	let uar_url = $('#userapprove').data('href');
	$.getJSON(uar_url).done(function(data) {
	    if("status_map" in data)
		$('#userapprove').data('status_map',data.status_map);
            if("uar" in data) {
                let incomplete = data.uar.filter(function(x) {
		    if('created_at' in x) {
			/* Skip data that is less than two weeks old */
			try {
			    let ctm = Date.parse(x.created_at);
			    let now = Date.now();
			    if((now - ctm) < two_weeks)
				return false;
			} catch(err) {
			    console.log("Date parsing error "+err);
			    console.log(x);
			}
		    }
		    /* UNKNOWN is same as PENDING */
		    return x.status == data.status_map.UNKNOWN; });
		if(incomplete.length) {
                    $('#userapprove').html(' [' +
					   String(incomplete.length) + ']' );
		    /*  use pending/user/(?P<pk>[0-9]+)/addcontact/ and
			create a prompt to start process */
		    if($('.uar-row').length) {
			/* Create a new Ticket by submitting data
			   to Vendor Queue */
			let divm = $('<div>').addClass('large-10 columns');
			incomplete.forEach(function(rec) {
			    let name = rec.full_name + " " ;
			    let row = $("<p>")
				.addClass("article-row-content-description")
				.text(name).append($("<span>")
						   .addClass("email")
						   .text(rec.username))
				.append(" ")
				.append($("<button>")
					.addClass("button")
					.html("Review"));
			    let divrow = $("<div>")
				.addClass("article-row-content")
				.append(row);
			    let picdiv = $("<div>")
				.addClass("profile-pic text-center")
				.css({"background-color": rgba_rand(255)})
				.append($("<span>").addClass("logo-initial")
					.text(name[0]));

			    let div = $("<div>").addClass("row list-row")
				.attr("id","uar-pk-"+String(rec.pk))
				.attr("data-rec",JSON.stringify(rec))
				.append($("<div>").addClass("large-1 columns")
					.append(picdiv))
				.append($("<div>").addClass("large-7 columns")
					.append(divrow));
			    $('.uar-row > .large-10').append(div);
			});
			$('.uar-row .list-row')
			    .on('click',function() {
				let rec = $(this).data('rec');
				let footer = $('<div>')
				    .addClass("modal-footer")
				    .append($("<div>")
					    .addClass("row column text-right")
					    .append($("<button>")
						    .addClass("button cmu")
						    .html("Reject"))
					    .append(" ")
					    .append($("<button>")
						    .addClass("button primary")
						    .html("Create Ticket"))
					   );
				if(rec) {
				    let l = get_modal();
				    l.data("rec",rec);
				    function dstatus(inp) {
					let ret = inp;
					 Object.keys(data.status_map)
                                            .forEach(function(x) {
						if(inp == data.status_map[x])
                                                    ret = x;
                                            }); console.log(l);
                                        return ret;
				    }
				    function dtime(inp) {
					try {
					    let m = Date.parse(inp);
					    return new Date(m).toLocaleString();
					} catch(err) {
					    console.log("Date parsing error "
							+ err);
					}
					return inp;
				    }
				    let tb = json_table(rec,
							{pk:false,
							 thread_url: false,
							 status: dstatus,
							 created_at: dtime});
				    $('#txmodal').html($("<div>")
						      .addClass("modal-body")
						      .append(tb))
					.append(footer);
				    $('#txmodal .cmu').on('click', reject_uar);
				    $('#txmodal .primary').on('click', tkt_uar);
				    let btnCancel = $('<button>')
					.addClass('close-button')
					.html("X")
					.on('click',function() {
					    $('#xmodal').foundation('close');
					});
				    $('#xmodal').append(btnCancel);
				}
			    });
		    } 
		} else {
		    $('.uar-row').hide();
		}
	    }
	}).fail(function() {
	    console.log("Error in getting UAR request for users pending");
	    console.log(arguments);
	});
    }
});
