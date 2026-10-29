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

$(document).foundation();

$(function() {
    $('.dateprinted').on('click',function(event) {
	event.preventDefault();
	let mdate = new Date();
	let unit = $(this);
	let formats = ["defaultISO","toLocaleString","toString"]
	let format = unit.attr("format");
	if(!format) {
	    try {
		mdate = new Date(Date.parse(unit.html()));
	    } catch(error) {
		console.log("Error parsing date field "+String(error));
		return;
	    }
	    unit.attr(formats[0],unit.html());	    
	    for(let i=1; i < formats.length; i++) {
		unit.attr(formats[i],mdate[formats[i]]());
	    }
	    unit.html(unit.attr(formats[1]));
	    unit.attr("format",formats[1]);
	    return;
	} 
	let findex = formats.findIndex(function(u) { return u == format});
	findex = (findex + 1) %3;
	if(unit.attr(formats[findex])) {
	    unit.html(unit.attr(formats[findex]));
	    unit.attr("format",formats[findex]);
	}

    });
    function put_unread(ucount,update) {
	if(ucount > 0) {
	    $('.unread_msg_count').html(String(ucount)).addClass("badge success");
	    if(update)
		sessionStorage.setItem('unread_msg_count',String(ucount));
	} else {
	    $('.unread_msg_count').html("").removeClass("badge success");
	    sessionStorage.removeItem('unread_msg_count');
	}
    }
    function update_unread() {
	let count = 0;
	if(sessionStorage.getItem('unread_msg_count')) {
	    /* On page load show current unread count and wait for Ajax data*/
	    count = parseInt(sessionStorage.getItem('unread_msg_count'));
	    if(count > 0)
		put_unread(count,false);
	}
	    
	if($('#unread_msg_count').length > 0 &&
	   $('#unread_msg_count').data('url')) {
	    $.getJSON($('#unread_msg_count').data('url'),function(d) {
		if(('unread' in d) && (d.unread != count))
		    put_unread(d.unread,true);
	    });
	}
    }
    update_unread();
    /* Every 5 minutes updates Inbox unread count */
    setTimeout(update_unread,300000);

    /* Push the fixed off-canvas side menus below the announcement banner.
       The side menus are position:fixed (pinned to the top of the viewport), so
       they slide underneath the header/banner and must be offset by the header's
       height to clear it. The banner's height varies with viewport width (its text
       wraps differently) and with each user's screen, so we measure the header live
       here instead of hardcoding px in the CSS.

       There are two states, both of which the base CSS hardcodes to 225px:
	 - normal / scrolling up: the off-canvas containers use padding-top;
	 - scrolling down: vince.js / vincecomm.js add the .less_padding (Comm) or
	   .less_padding_vt (Track) class to ul.vincesidemenu, switching it to
	   position:absolute with a fixed `top`.
       We drive both from the measured height via one injected stylesheet rule.
       !important is needed to beat the static rules (the container padding-top is
       set with an ID selector; the .less_padding rules already use !important, so
       our later-in-DOM rule wins on equal specificity). */
    function align_sidemenus_below_banner() {
	/* Only intervene while a banner is actually present; otherwise leave the
	   CSS defaults (the no-banner values) untouched. */
	if ($('.announcement-banner').length === 0) {
	    return;
	}
	var header = document.getElementById('header');
	if (!header) {
	    return;
	}
	/* getBoundingClientRect().height is the header's rendered box height, which
	   is scroll-independent and correct whether the header is in normal flow
	   (VINCE Comm) or stuck to the top (VINCE Track's sticky header). */
	var offset = Math.ceil(header.getBoundingClientRect().height);
	var style = document.getElementById('banner-sidemenu-offset');
	if (!style) {
	    style = document.createElement('style');
	    style.id = 'banner-sidemenu-offset';
	    document.head.appendChild(style);
	}
	style.textContent =
	    '#offCanvasLeft, #offCanvasLeft1, #TRoffCanvasLeft, #TRoffCanvasLeft1 ' +
	    '{ padding-top: ' + offset + 'px !important; }\n' +
	    '.less_padding, .less_padding_vt { top: ' + offset + 'px !important; }';
    }
    align_sidemenus_below_banner();
    /* Re-measure after full load (fonts/images can change the banner height) and
       whenever the viewport is resized (which can re-wrap the banner text). */
    $(window).on('resize load', align_sidemenus_below_banner);
    /* Remember the banner's collapsed/expanded choice across page loads (VINCE Comm).
       The <details> is hardcoded `open`, so without this it re-expands on every
       navigation. We store the choice in localStorage, keyed by a hash of the
       announcement text so a NEW announcement re-shows even if the user hid the old
       one. Storage access is wrapped in try/catch (private mode can throw). */
    function announcement_storage_key() {
	var text = $('.announcement-banner').text().replace(/\s+/g, ' ').trim();
	var hash = 0;
	for (var i = 0; i < text.length; i++) {
	    hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
	}
	return 'vince_announcement_hidden_' + hash;
    }
    function remember_announcement_state(isOpen) {
	try {
	    if (!window.localStorage) return;
	    if (isOpen) {
		localStorage.removeItem(announcement_storage_key());
	    } else {
		localStorage.setItem(announcement_storage_key(), '1');
	    }
	} catch (e) { /* storage unavailable (private mode / disabled) — ignore */ }
    }

    /* The banner is a collapsible <details> that lives inside the Foundation Sticky
       header (.headernav). Sticky caches the header height and pins an inline height
       on the #header container, so collapsing/expanding the banner leaves stale blank
       space (and makes align_sidemenus_below_banner measure the old height) unless we
       force Sticky to recompute. On toggle: remember the choice, ask Sticky to
       re-measure via its resizeme.zf.trigger hook, then re-align the side menus on the
       next frame once the header height has settled. (toggle does not bubble, so bind
       it directly.) */
    $('.announcement-banner').on('toggle', function () {
	remember_announcement_state(this.open);
	$('.headernav').trigger('resizeme.zf.trigger');
	if (window.requestAnimationFrame) {
	    window.requestAnimationFrame(align_sidemenus_below_banner);
	} else {
	    align_sidemenus_below_banner();
	}
    });

    /* On load, re-apply a previously chosen "hidden" state. Removing the `open`
       attribute fires the toggle handler above, which recomputes the layout for us. */
    try {
	if ($('.announcement-banner').length && window.localStorage &&
	    localStorage.getItem(announcement_storage_key()) === '1') {
	    $('.announcement-banner').removeAttr('open');
	}
    } catch (e) { /* ignore */ }
});

