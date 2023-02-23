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
$(document).ready(function() {

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
					     $("#appendlist").append('<li>'+response.filename+"<a title=\"remove this file from the published files\" href=\"" + response.remove_link + "\" class=\"file-remove\"><i class=\"fas fa-trash\"></i></a></li>");
					 },
				     }).then((url) => onSuccess(imageUrl))
				 },
				 renderingConfig: {
                                       singleLineBreaks: false,
                                   }
				});

    simplemde.codemirror.on('change', function(cm, change){
	const {anchor, head}  = simplemde.codemirror.findWordAt({
        line: change.to.line, //tried many positions, seems to identify words correctly. 
        ch: change.to.ch
	});
	simplemde.codemirror.doc.markText(anchor,head, {
            css: 'color:#b00;font-weight:600;background-color:#f8f8f8;',
	});
	//TextMarker {lines: Array(1), type: "range", doc: Doc, id: 1, css: "color:FE3"}
    })


    if (document.getElementById('readonly')) {
	simplemde.codemirror.setOption('readOnly', true);
    }
    
    Array.prototype.indexOfForArrays = function(search)
    {
	var searchJson = JSON.stringify(search); // "[3,566,23,79]"
	var arrJson = this.map(JSON.stringify); // ["[2,6,89,45]", "[3,566,23,79]", "[434,677,9,23]"]
	
	return arrJson.indexOf(searchJson);
    };


    
    $(document).on("click", "#approveform button", function(event) {
	event.preventDefault();
	if ($(this).attr("value") == 2) {
	    submitform(true, true);
	} else if ($(this).attr("value") == 1)  {
	    submitform(true, false);
	}
	$("#modal").foundation("close");
	
    });

    
    $(document).on("click", "#reviewform button", function(event) {
	if ($(this).attr("value") == 2) {
	    // prompt for approval
	    event.preventDefault();
	    $("#modal").foundation("open");
	} else if ($(this).attr("value") == 1) {
	    event.preventDefault();
	    submitform(false, false);
	}
    });


    function submitform(complete, approved) {
	var allmarks = simplemde.codemirror.doc.getAllMarks();
	var array = [];
	for (var i=0; i<allmarks.length; i++) {
	    var x = [allmarks[i].find().from.ch, allmarks[i].find().from.line, allmarks[i].find().to.ch, allmarks[i].find().to.line];
	    var f = array.indexOfForArrays([x[0], x[1], x[2]-1, x[3]]);
	    if (f < 0) {
		array.push(x);
	    } else {
		array.splice(f, 1, x);
		
	    }
	    
	}
	
	var formdata = $('#reviewform').serializeArray()
	formdata.find(item => item.name == 'content').value=simplemde.value();

	formdata.push({'name': 'marks', 'value': JSON.stringify(array)});
	formdata.push({'name': 'completed', 'value': complete});
	formdata.push({'name': 'approved', 'value': approved});
	formdata.push({'name': 'save', 'value': 1});
	
	
	$.post($("#reviewform").attr("action"), formdata,
               function(data) {
		   window.location = data["redirect"];
               });
	
    }


    function applyMarkers(){
        var arrSavedMarkers = JSON.parse(document.getElementById('marks').textContent);
        for(var i=0; i<arrSavedMarkers.length; i++)
        {
            var marker = arrSavedMarkers[i];
            simplemde.codemirror.doc.markText(   {'ch': marker[0], 'line': marker[1] },  {'ch': marker[2], 'line': marker[3] }, { css: "color:#b00;font-weight:600;background-color:#f8f8f8;"});
        }    
    }

    if (document.getElementById('marks')) {
	applyMarkers();
    }

    $(document).on("click", "#applyreview", function(event) {
	event.preventDefault();
	$.ajax({
	    url: $(this).attr("href"),
	    type: "GET",
	    success: function(data) {
		$("#modal").html(data).foundation('open');
	    }
	});
    });

    
});


    

