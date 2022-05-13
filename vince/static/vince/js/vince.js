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
//Emily Test

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?                                                                                                          
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
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

});



