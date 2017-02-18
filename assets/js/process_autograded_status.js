/**
 * Created by Ilya V. Schurov on 19/02/2017.
 */

$(function() {
    $(".process_autograded_status")
        .each(function process_element(i, element) {
            element = $(element);
            var submission_id = element.data("submission-id");

            $.getJSON($SCRIPT_ROOT +
                "/json/autograded_status/" + submission_id,
                function(submission) {
                    if (submission.status === 'autograded') {
                        element.empty().append(
                            $("<a>").attr("href", $SCRIPT_ROOT
                            + "/get/feedback/" + submission_id)
                                .html("Результаты проверки")
                            );

                    } else if (submission.status === 'processing') {
                        element.text(
                            "Идёт автоматическая проверка. " +
                            "Пожалуйста, подождите."
                        );
                        setTimeout(process_element(i, element), 1000);
                    } else if (submission.status === 'failed') {
                        element.text("ОШИБКА: " + submission.log);
                    } else if (submission.status === 'late') {
                        element.text("Проверка не производится: работа " +
                            "сдана после дедлайна. Пожалуйста,  " +
                            "обратитесь к преподавателю, если считаете, " +
                            "что работа " +
                            "всё равно должна быть проверена.");
                    } else if (submission.status === 'sent-to-grading') {
                        element.text("Работа ожидает автоматической " +
                            "проверки, но все роботы-проверяльщики " +
                            "заняты. Пожалуйста, подождите.");
                        setTimeout(process_element(i, element), 1000);
                    } else if (submission.status == 'timeout') {
                        element.text("ОШИБКА: выполнение " +
                            "занимает слишком  " +
                            "много времени, скорее всего где-то есть " +
                            "бесконечный цикл.");
                    }
                }
            );
        });
});