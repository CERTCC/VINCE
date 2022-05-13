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

function reloadVendors() {
    var vuid = $("#vuid").html();
    var url_mask="/vuls/vendor/VU%23" + vuid;
    $("#accordion").replaceWith("<div class='loading_gif'></div>");
    $.get(url_mask)
	.done(function(data, textStatus, jqXHR) {
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
    var vuid = $("#vuid").html();
    var url_mask="/vuls/vendorstatus/VU%23" + vuid;
    $("#accordion").replaceWith("<div class='loading_gif'></div>");
    $.ajax({
     url: url_mask,
     success: function(data) {
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

function printvunote() {
   $('.accordion-expand-collapse a').click();
   javascript:window.print();
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
	var status = this.value;
	var info = $("#info_checkbox").hasClass('checked');
	var hidesort = $("#hidesort").attr("method");
	var sort = $("#vendorsort option:selected").val();
	$(".more-vendors").hide();
	if (status == "all") {
	    if ((hidesort == "status") && (sort == "alpha")) {
		reloadVendors();
		showVendors($("#vendorstatus option:selected").val(), $("#info_checkbox").hasClass('checked'));
                $("#hidesort").attr("method", "alpha");
		return true;
	    } else if (hidesort != sort) {
		reloadVendorsStatus();
		showVendors($("#vendorstatus option:selected").val(), $("#info_checkbox").hasClass('checked'));
                $("#hidesort").attr("method", "status");
		return true;
	    }
	}
	showVendors(status, info);
    });

    $("#vendorsort").on("change", function() {
	var sort = this.value;
	var status = $("#vendorstatus option:selected").val();
	$(".more-vendors").hide();
	if (status == "all") {
	    if (sort == "alpha") {
		reloadVendors();
		$("#hidesort").attr("method", "alpha");
		
            } else {
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
