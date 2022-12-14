/*#########################################################################
  # VINCE
  #
  # Copyright 2022 Carnegie Mellon University.
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

function asyncLoad(fdiv,furl,fmethod,pdiv,formpost,silent) {
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
    window.txhr = $.ajax({
        url : furl,
        type: fmethod,
        data: fdata,
        success: function(data) {
	    lockunlock(false,pdiv,fdiv);
	    $(fdiv).html(data);
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
	    asyncLoad(fdiv,furl,fmethod,pdiv,formpost,true);
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
    

});
