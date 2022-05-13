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
function onBeforeUnload(e) {
    e.preventDefault();
    e.returnValue = '';
    return;
}


$(document).ready(function() {

    window.addEventListener('beforeunload', onBeforeUnload);


    $('form').on('submit', function (e) {
	var $form = $(this);	
	window.removeEventListener('beforeunload', onBeforeUnload);

	if ($form.data('submitted') === true) {
	    // Previously submitted - don't submit again
	    e.preventDefault();
	} else {
	    // Mark it so that the next submit can be ignored
	    $form.data('submitted', true);
	}

	return this;
	
    });

    
    $( "#selectable" ).selectable({
	cancel: 'a',
	filter: "li"
    });

    var simplemde = new EasyMDE({element: $("#id_content")[0],
				   previewRender: function(plainText) {
				       var preview = document.getElementsByClassName("editor-preview-side")[0];
				       preview.innerHTML = this.parent.markdown(plainText);
				       preview.setAttribute('id','editor-preview');
				       MathJax.texReset();
				       MathJax.typesetClear();
				       MathJax.startup.promise.then(function () {
					   MathJax.typesetPromise(["#editor-preview"])
					       .catch(function (err) {
						   //
						   //  If there was an internal error, put the message into the output instead
						   //
						   alert(err.message);
					       });
				       });
				       return preview.innerHTML;
				   },
				 autoDownloadFontAwesome: false,
				 uploadImage:true,
				 hideIcons: ['image'],
				 showIcons: ['upload-image'],
				 //imageUploadEndpoint: '/vince/upload/',
				 imageUploadFunction: function(file, onSuccess, onError) {
				     var form_data = new FormData();
				     form_data.append('file', file);
				     var imageUrl;
				     var cookie = getCookie('csrftoken');
				     form_data.append('csrfmiddlewaretoken', cookie);
				     form_data.append('case_id', $("#case_id").html());
				     form_data.append('pathname', window.location.pathname);
				     console.log(form_data);
				     $.ajax({
					 url: "/vince/upload/",
					 data: form_data,
					 processData: false,
					 contentType: false,
					 dataType: 'json',
					 type: "POST",
					 success: function(response) {
					     console.log(response.image_url);
					     imageUrl = response.image_url;
					     $("#appendlist").append('<input type="hidden" name="vincefiles[]" value="'+response.id+'"><li>'+response.filename+"<a title=\"remove this file from the published files\" href=\"" + response.remove_link + "\" class=\"file-remove\"><i class=\"fas fa-trash\"></i></a></li>");
					 },
					 error:  function(xhr, status) {
					     addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error when uploading file. Image may be too large (max 2Mb).</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');

					 },
				     }).then((url) => onSuccess(imageUrl))
				 },
				 renderingConfig: {
                                       singleLineBreaks: false,
                                   }
				  });
    
    $(document).on("change", '.artifact_check', function(event) {

	if (event.target.checked) {
	    var simplemdvalue = simplemde.value();
	    var id = $(this).val();
	    var url = $(this).attr("href");
	    var cookie = getCookie('csrftoken');

	    $.ajax({
                url: url,
                type: "POST",
		data: {'csrfmiddlewaretoken': cookie},
                success: function(data) {
                    simplemde.value(simplemdvalue + data["text"]);
		    if ("remove_link" in data) {
			$("#appendlist").append('<input type="hidden" name="vincefiles[]" value="'+data["id"]+'"><li>'+data.filename+"<a title=\"remove this file from the published files\" href=\"" + data.remove_link + "\" class=\"file-remove\"><i class=\"fas fa-trash\"></i></a></li>");
		    }
		}
            });
	    
	    /*$.ajax({
		url: "/vince/artifact/detail/"+id+"/",
		type: "GET",
		success: function(data) {
		    simplemde.value(simplemdvalue + data);
		}
	    });*/

	} else {
	    var simplemdvalue = simplemde.value();
	    var lines = simplemdvalue.split('\n');
	    var title = $(this).attr('title');
	    console.log(title)
	    var regex = "\["+title+"\]";
	    var nextregex = "###"
	    var found = false;
	    for (var i=0; i<lines.length; i++) {
		if (found) {
		    if (lines[i].startsWith(nextregex)) {
			found=false;
			break;
		    } else {
			lines.splice(i,1);
			i--;
			continue;
		    }
		}
		if (lines[i].startsWith(regex)) {
		    found = true;
		    lines.splice(i,1);
		    console.log("FOUND");
		    i--;
		    continue;
		}
	    }
	    var newtext = lines.join('\n');
	    simplemde.value(newtext);
	}
    });


    $(document).on("click", '.viewtext', function(event) {
	event.preventDefault();
	$(this).parent().next().toggle();
	$(this).children().toggleClass("fa-eye-slash", "fa-eye");
    });
    
    $(document).on("click", '.transferbutton', function(event) {
	event.preventDefault();
	$(".ui-selected").each(function() {
	    if ($(this).children(".liheader").text() != "" ) {
		var simplemdvalue = simplemde.value();
		var header = "\n#### " + $(this).children(".liheader").text()+"####\n";
		
		simplemde.value(simplemdvalue + header+ $(this).children(".licontent").html().replace(/<br>/g,"\n"));
	    }
	});
    });

    var addmodal = $("#confirmmodal");
    

    $(document).on("click", "#syncrefs", function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
	$.ajax({
	    url: url,
	    type: "GET",
	    success: function(data) {
		var lines = data.join("\r\n");
		$("#id_references").val(lines);
	    }
	});
	       
    });


    $(document).on("click", '.file-remove', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    });

    $(document).on("submit", '#rmfileform', function(event) {
	event.preventDefault();
	$.post($(this).attr("action"),
	       $(this).serializeArray(),
	       function(data) {
		   $("#filelist").html(data);
	       })
	    .fail(function(d) {
		alert("An error occurred while trying to remove this file.");
	    });
    
        addmodal.foundation('close');
    });
    
    $(document).on("change", '.vul_check', function(event) {

        if (event.target.checked) {
            var simplemdvalue = simplemde.value();
            var id = $(this).val();
            $.ajax({
                url: "/vince/case/vul/detail/"+id+"/",
                type: "GET",
                success: function(data) {
                    simplemde.value(simplemdvalue + data);
                }
            });
	} else {
            var simplemdvalue = simplemde.value();
            var lines = simplemdvalue.split('\n');
            var title = $(this).attr('title');
            var regex = "**"+title+"**";
	    console.log(regex)

            var nextregex = "###"
            var found = false;
            for (var i=0; i<lines.length; i++) {
                if (found) {
                    if (lines[i].startsWith(nextregex)) {
                        found=false;
                        break;
                    } else {
                        lines.splice(i,1);
                        i--;
                        continue;
                    }
                }
		console.log(lines[i])
                if (lines[i] == regex) {
                    found = true;
                    lines.splice(i,1);
                    console.log("FOUND");
                    i--;
                    continue;
                }
            }
            var newtext = lines.join('\n');
            simplemde.value(newtext);
        }
    });


});
