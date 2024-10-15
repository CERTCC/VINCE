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

function reloadVendors() {
    // console.log('reloadVendors is now running')
    var vuid = $("#vuid").html();
    // console.log('vuid is ' + vuid)
    var url_mask="/vuls/vendor/VU%23" + vuid;
    // console.log('url_mask is ' + url_mask)
    $("#accordion").replaceWith("<div id='accordion' class='ui-accordion ui-widget ui-helper-reset'><div class='loading_gif'></div></div>");
    $.get(url_mask).done(function(data, textStatus, jqXHR) {
        // console.log('the data returned from the get request sent out by reloadVendors is ' + data)
        $("#vendorinfo").html(data);
	    $("#accordion").accordion({
            header: '.accordion-header',
            icons: false,
            heightStyle: "content",
            active: false,
            collapsible: true,
	    });
	    if ($("#info_checkbox").hasClass('checked')) {
            showVendors($("#vendorstatus option:selected").val(), true);
            $(".more-vendors").hide();
        }
	});
}

function reloadVendorsStatus() {
    // console.log('reloadVendorStatus is running')
    var vuid = $("#vuid").html();
    // console.log('vuid is ' + vuid)
    var url_mask="/vuls/vendorstatus/VU%23" + vuid;
    // console.log('url_mask is ' + url_mask)
    $("#accordion").replaceWith("<div id='accordion' class='ui-accordion ui-widget ui-helper-reset'><div class='loading_gif'></div></div>");
    $.ajax({
        url: url_mask,
        success: function(data) {
            // console.log('the data returned from the get request sent out by reloadVendorStatus is ' + data)
            $("#vendorinfo").html(data);
            $("#accordion").accordion({
                header: '.accordion-header',
                icons: false,
                heightStyle: "content",
                active: false,
                collapsible: true,
            });
            if ($("#info_checkbox").hasClass('checked')) {
                showVendors($("#vendorstatus option:selected").val(), true);
                $(".more-vendors").hide();
            }
        }
   });
}

async function printvunote() {
    /*
      Preferably use addClass and removeClass shortcuts
      and css appropriate to show relevant content only
     */
    $('body').addClass("print-friendly");
    $('.callout.primary').hide();
    $('.topbar-redbar').hide();
    $('.site-title').hide();
    $('.site-subtitle').hide();
    $('.top-bar').hide();
    $('nav').hide();
    $('.sticky-container').hide();
    $('.small-text-left').hide();
    $('.accordion-header').click();
    $('#moreVendorsLink').click();
    $('#sponsorbar').hide();
    $('#bottombar').hide();
    $('#footer').hide();
    $('.accordion-expand-collapse a').click();
    await window.print();
    console.log("done printing");
    $('body').removeClass("print-friendly");
    $('.callout.primary').show();
    $('.topbar-redbar').show();
    $('.site-title').show();
    $('.site-subtitle').show();
    $('.top-bar').show();
    $('nav').show();
    $('.sticky-container').show();
    $('.small-text-left').show();
    $('#sponsorbar').show();
    $('#bottombar').show();
    $('#footer').show();
}

function showInfo() {
    var status = $("#vendorstatus option:selected").val();
    $("[data-type='accordion-section']").each(function () {
        $(this).show();
        if (!($(this)[0].classList.contains("info"))) {
            if ($(this).css("display") == "block") {
                $(this).hide();
            }
        } else {
            if(!($(this)[0].classList.contains(status))) {
                if ($(this).css("display") == "block") {
                    $(this).hide();
                }
            }
        }
    });
}

function showAll() {
    $("[data-type='accordion-section']").each(function () {
        $(this).show();
    });
}


function showVendors(status, info) {
    $("[data-type='accordion-section']").each(function () {
        $(this).hide();
	if (info) {
	    if (!($(this)[0].classList.contains("info"))) {
		return true;
	    }
	}
	if (status == "all") {
	    $(this).show();
	} else {
	    if ($(this)[0].classList.contains(status)) {
		$(this).show();
	    }
	}
    });
}




$(document).ready(function() {

    $("#accordion").accordion({
        header: '.accordion-header',
        icons: false,
        heightStyle: "content",
        active: false,
        collapsible: true,
    });

    
    $(document).on("click", '#moreVendorsLink', function(e) {
        $(".extravendors").toggle();
	    $(".moreVendors").toggle();
        $(".lessVendors").toggle();
        e.preventDefault();
    });

    $(document).on("click", '#lessVendorsLink', function(e) {
        $(".extravendors").toggle();
	    $(".moreVendors").toggle();
        $(".lessVendors").toggle();
        e.preventDefault();
    });

    $(document).on("click", ".popup-print", function(e) {
        e.preventDefault();
        printvunote();
    });
    

    /* this is to expand appropriate vendor record in accordion */
    var hash = window.location.hash;
    var anchor = $('a[href$="'+hash+'"]');
    if (anchor.length > 0){
        anchor.click();
        $("#moreVendorsLink").trigger("click");
    }

    /* this is to scroll to that newly opened vendor record */
    $('#accordion').bind('accordionactivate', function(event, ui) {
        /* In here, ui.newHeader = the newly active header as a jQ object
              ui.newContent = the newly active content area */
        if (ui.newHeader[0]) {
            $( ui.newHeader )[0].scrollIntoView();
        }
    });
    

    $("#vendorstatus").on("change", function() {
        // console.log('javascript is handling a change to #vendorstatus')
        var status = this.value;
        // console.log('status is ' + status)
        var info = $("#info_checkbox").hasClass('checked');
        // console.log('info is ' + info)
        var hidesort = $("#hidesort").attr("method");
        // console.log('hidesort is ' + hidesort)
        var sort = $("#vendorsort option:selected").val();
        // console.log('sort is ' + sort)
        $(".more-vendors").hide();
        if (status == "all") {
            if ((hidesort == "status") && (sort == "alpha")) {
                // console.log('javascript is in the block of code where it is found that hidesort == "status"')
                reloadVendors();
                showVendors($("#vendorstatus option:selected").val(), $("#info_checkbox").hasClass('checked'));
                $("#hidesort").attr("method", "alpha");
                return true;
            } else if (hidesort != sort) {
                // console.log('javascript is in the block of code where it is found that hidesort != sort')
                reloadVendorsStatus();
                showVendors($("#vendorstatus option:selected").val(), $("#info_checkbox").hasClass('checked'));
                $("#hidesort").attr("method", "status");
                return true;
            } else {
                // console.log('none of the conditions for which pre-existing code was prepared obtains')
            }
        }
        showVendors(status, info);
    });

    $("#vendorsort").on("change", function() {
        // console.log('javascript is handling a change to #vendorsort')
        var sort = this.value;
        // console.log('sort is ' + sort)
        var status = $("#vendorstatus option:selected").val();
        // console.log('status is ' + status)
        $(".more-vendors").hide();
        if (status == "all") {
            if (sort == "alpha") {
                // console.log('javascript is in the block of code where it is found that sort == "alpha"')
                reloadVendors();
                $("#hidesort").attr("method", "alpha");
            } else {
                // console.log('javascript is in the block of code where it is not found that sort == "alpha"')
                reloadVendorsStatus();
                $("#hidesort").attr("method", "status");
            }
        }
    });

    $("#info_checkbox").on("change", function() {
        $(".more-vendors").hide();
        $("#info_checkbox").toggleClass('checked');
        if ($("#info_checkbox").hasClass('checked')) {
            showVendors($("#vendorstatus option:selected").val(), true);
        } else {
            showVendors($("#vendorstatus option:selected").val(), false);
        }
    });
			 

    
    $('.popup-twitter').popupWindow({
        height:400,
        width:575,
        top:50,
        left:50
    });

    $('.popup-facebook').popupWindow({
        height:500,
        width:900,
        top:50,
        left:50
    });

    $('.popup-share').popupWindow({
        height:500,
        width:900,
        top:50,
        left:50
    });

    $('.accordion-expand-collapse a').click(function() {
        $('#accordion .ui-accordion-header:not(.ui-state-active)').next().slideToggle();
        $(this).text($(this).text() == 'Expand all' ? 'Collapse all' : 'Expand all');
        $(this).toggleClass('collapse');
        return false;
    });

});
