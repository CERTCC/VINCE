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
});

