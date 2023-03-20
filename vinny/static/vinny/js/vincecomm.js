/*
  #########################################################################
  # VINCE
  #
  # Copyright 2023 Carnegie Mellon University.
  #
  # NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
  # INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
  # UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
  # AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  # PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF 
  # THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY
  # KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
  # INFRINGEMENT.
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
  # This Software includes and/or makes use of Third-Party Software each 
  # subject to its own license.
  #
  # DM21-1126
  ########################################################################
*/
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie
						 .substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
function to_locale(df) {
    try {
	/* Check if already processed or the if the element is visible
	  and return quietly*/
	if(df.classList.contains('locale-processed'))
	    return;
	if(df.offsetParent == null)
	    return;
	let epoch_ms = Date.parse(df.innerHTML);
	if(isNaN(epoch_ms)) {
	    console.log("Invalid Date "+df.innerHTML);
	    return;
	}
        let d = new Date(epoch_ms);
	df.title = df.innerHTML;
        if(df.classList.contains('datefield'))
	    df.innerHTML = d.toLocaleDateString();
        if(df.classList.contains('datetimefield'))
	    df.innerHTML = d.toLocaleString();
	df.classList.add('locale-processed');
    } catch(err) {
        console.log("Date field parsing error "+String(err));
    }
}
function update_locales() {
    $('.datetimefield,.datefield').each(function(_,el) {
	to_locale(el);
    });
}

$(function () {

    $('span[title]').qtip({
        style: {classes: 'qtip-youtube'}
    });

    $('i[title]').qtip({
        style: {classes: 'qtip-youtube'}
    });
    
    var prev = 0;
    var $window = $(window);
    var nav = $('ul.vincesidemenu');

    $window.on('scroll', function(){
        var scrollTop = $window.scrollTop();
        nav.toggleClass('less_padding', scrollTop > prev);
        prev = scrollTop;
    });
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
    function filter_navli(e) {
	let li = $(e.currentTarget || e.target || e.srcElement);
	li.parent().find('.fa-check').css('opacity',0);
	li.find('.fa-check').css('opacity',1);
	let rowdiv = li.closest('div.row');
	let statusd = "[" + li.html() + "]";
	if(rowdiv.find('.statusd_view').length) {
	    rowdiv.find('.statusd_view').html(statusd);
	} else {
	    rowdiv.append($('<div>').addClass('statusd_view').html(statusd));
	}
	rowdiv.find('.statusd_view i').addClass('fa-filter');
	let partdiv = li.closest('.participant_type');
	let all = partdiv.find('.participant').not('.pheader');
	let moreless = partdiv.find(".moreless");
	let data = moreless.data();
	if('asyncdivid' in data)
	    $('#' + data.asyncdivid).show()
	if(li.hasClass('all')) {
	    all.show();
	    moreless.show();
            let all_count = all.length
	    li.find('.count').html(all_count);
	} else {
	    all.hide();
	    moreless.hide();
	    let aclass = $(li).data('class');
	    all.find('.'+aclass).closest('.participant').show()
	}
    }
    function activate_navli(nav) {
	let partdiv = $(nav).closest('.participant_type');
	let all = partdiv.find('.participant').not('.pheader');
	let all_count = all.length;
	
	$(nav).find('li li').each(function(_,li) {
	    $(li).off('click');
	    $(li).on('click',filter_navli);
	    if($(li).hasClass('all')) {
		$(li).find('.count').html(all_count);
		$(li).find('.fa-check').css('opacity',1);
	    } else {
		let aclass = $(li).data('class');
		if(aclass) {
		    let count = partdiv.find('.'+aclass).length;
		    $(li).find('.count').html(count);
		}
		$(li).find('.fa-check').css('opacity',0);		
	    }
	})
    }
    $('nav.cdown').each(function(_,nav) {
	activate_navli(nav);
    });

    async function asyncshowall(adiv,clicked) {
	let dad = $(adiv).parent();
	if(clicked) {
	    $(adiv).hide();	    
	    dad.find('.asyncshowless').show();
	}
	let data = dad.data(); 
	if('asyncdivid' in data) {
	    let asyncdiv = $('#' + data.asyncdivid);
	    if(clicked)
		asyncdiv.show();
	    let href = data.href;
	    let rowdiv = data.rowdivclass;
	    let pdiv = data.parentdivclass;
	    let total = parseInt(dad.find('.showallcount').html());
	    let batch = parseInt(data.batchcount);
	    if(isNaN(batch))
		batch = 20;
	    let count = $('.'+data.parentdivclass + ' .' +
			  data.rowdivclass).length;
	    let maxloop = 1000;
	    let loop = 0;
	    let nav = $('.'+pdiv).find("nav.cdown");
	    /* Hide the filter till all the rows are loaded */
	    if(count < total)
		$(nav).hide();
	    while ( count < total) {
		if(loop > maxloop) {
		    console.log("Breaking due to too many loops");
		    break;
		}
		loop++;
		let hurl = href + "?start=" + String(count-1) + 
		    "&end=" + String(count + batch); 
	        
		await $.get(hurl).done(function(w) {
		    asyncdiv.append(w);
		    count = $('.'+data.parentdivclass +
			      ' .' + data.rowdivclass).length;
		});
	    }
	    if(count >= total) {
		console.log("Activate the filter button");
		if(nav)
		    activate_navli(nav[0]);
		$(nav).show();
	    }
	}
    }
    
    $('.asyncshowall').each(function(_,adiv) {
	$(adiv).on('click',function(e) {
	    asyncshowall(adiv,true);
            e.preventDefault();
	    e.stopPropagation();
	});
	asyncshowall(adiv,false);
    });

    $('.asyncshowless').on('click',function(e) {
	$(this).hide();
	let dad = $(this).parent();	
	dad.find('.asyncshowall').show()
	let data = dad.data();
        if('asyncdivid' in data) {
            let asyncdiv = $('#' + data.asyncdivid);
	    asyncdiv.hide();
	}
        e.preventDefault();
	e.stopPropagation();
    });
    update_locales();
});
