/**
 * Created by Ilya V. Schurov on 19/02/2017.
 */

$(function() {
    $(".process_autograded_status")
        .each(function process_element(i, element) {
            element = $(element);
            var submission_id = element.data("submission-id");

            function process_submission(submission) {
                var status = submission.status;
                var log = submission.log;
                if (status === 'autograded') {
                    element.empty().append(
                        $("<a>").attr("href", $SCRIPT_ROOT
                        + "/get/feedback/" + submission_id)
                            .html("Результаты проверки")
                        );

                } else if (status === 'processing') {
                    element.text(
                        "Идёт автоматическая проверка. " +
                        "Пожалуйста, подождите."
                    ).append(
                        $("<img>").attr("src", $SCRIPT_ROOT +
                            "/assets/images/3-1.gif"));
                    setTimeout(process_element(i, element), 1000);
                } else if (status === 'failed') {
                    element.text("ОШИБКА: " + log);
                } else if (status === 'late') {
                    element.text("Проверка не производится: работа " +
                        "сдана после дедлайна. Пожалуйста,  " +
                        "обратитесь к преподавателю, если считаете, " +
                        "что работа " +
                        "всё равно должна быть проверена.");
                } else if (status === 'sent-to-grading') {
                    element.text("Работа ожидает автоматической " +
                        "проверки, но все роботы-проверяльщики " +
                        "заняты. Пожалуйста, подождите.").append(
                        $("<img>").attr("src", $SCRIPT_ROOT +
                            "/assets/images/3-1.gif"));

                    setTimeout(process_element(i, element), 1000);
                } else if (status == 'timeout') {
                    element.text("ОШИБКА: выполнение " +
                        "занимает слишком  " +
                        "много времени, скорее всего где-то есть " +
                        "бесконечный цикл.");
                }
            }

            var status = element.data("autograded-status");
            if (status == 'autograded' || status == 'late' ||
                    status == 'timeout') {
                process_submission({status: status})
            } else {
                $.getJSON($SCRIPT_ROOT +
                    "/json/autograded_status/" + submission_id,
                    process_submission
                );
            }
        });
});