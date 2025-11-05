#include <QApplication>
#include <QDialog>
#include <QFont>
#include <QGridLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QMutex>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <Qt>
#include <QThread>
#include <QVBoxLayout>
#include <QWidget>

import std;
import json;
import snet.constants;
import snet.manager.ds_manager;
import snet.manager.key_manager;
import snet.manager.profile_manager;
import snet.utils.files;
import snet.utils.encoding;

constexpr auto NODE_COUNT = 14;
constexpr auto DIR_NODE_COUNT = 4;
constexpr auto W = 6;
constexpr auto H = 3;


class LogMessageDisplay final : public QPlainTextEdit {
    Q_OBJECT

public:
    explicit LogMessageDisplay(QWidget *parent = nullptr) {
        setLayout(new QVBoxLayout());
        setFont(QFont("JetBrains Mono", 5));
        layout()->setAlignment(Qt::AlignTop);
        document()->setMaximumBlockCount(10'000);
        setReadOnly(true);
        setTextInteractionFlags(Qt::NoTextInteraction);
    }

    auto add_new_log_message(std::string const &message) -> void {
        appendPlainText(QString::fromStdString(message));
    }

    auto get_all_messages() const -> std::string {
        return toPlainText().toStdString();
    }
};


class LogMessageScroller final : public QScrollArea {
    Q_OBJECT
    std::size_t node_id;
    LogMessageDisplay *log_display;
    QMutex io_lock;
    QProcess *process = nullptr;

public:
    explicit LogMessageScroller(
        const std::size_t node_id,
        const bool is_directory_service,
        QWidget *parent = nullptr) :
        QScrollArea(parent),
        node_id(node_id),
        log_display(new LogMessageDisplay()) {
        setWidgetResizable(true);
        setWidget(log_display);

        // Connect the signal for receiving new log messages.
        connect(this, &LogMessageScroller::recv_new_log_message, this, [this](std::string const &message) {
            log_display->add_new_log_message(message);
            scroll_to_bottom();
        });

        // Thread the node process to avoid blocking the UI.
        is_directory_service ? run_dir_process() : run_node_process();
    }

    auto scroll_to_bottom() const -> void {
        verticalScrollBar()->setValue(verticalScrollBar()->maximum());
    }

    auto mousePressEvent(QMouseEvent *event) -> void override {
        const auto dialog = new QDialog();
        dialog->setLayout(new QVBoxLayout());
        dialog->layout()->setAlignment(Qt::AlignTop);
        dialog->setWindowTitle(QString::fromStdString("Node " + std::to_string(node_id) + " Log Messages"));
        dialog->setFixedSize(800, 600);
        dialog->setWindowOpacity(0.9);

        const auto log_viewer = new QPlainTextEdit();
        log_viewer->setReadOnly(true);
        log_viewer->setFont(QFont("JetBrains Mono", 10));
        log_viewer->setPlainText(log_display->toPlainText());
        log_viewer->moveCursor(QTextCursor::End);
        log_viewer->setTextInteractionFlags(Qt::NoTextInteraction);

        const auto save_to_file_button = new QPushButton("Save to file");
        connect(save_to_file_button, &QPushButton::clicked, this, [this] {
            const auto filename = "node_" + std::to_string(node_id) + "_logs.txt";
            const auto file_content = log_display->get_all_messages();
            snet::utils::write_file(std::filesystem::path("../../logs") / filename, file_content);
        });

        dialog->layout()->addWidget(log_viewer);
        dialog->layout()->addWidget(save_to_file_button);
        dialog->show();
    }

    auto run_node_process() -> void {
        const auto username = std::string("node.") + std::to_string(node_id);
        const auto password = std::string("pass.") + std::to_string(node_id);
        const auto cmd = std::string("../snet join --name ") + username + std::string(" --pass ") + password;

        // Create the process and link the logging to pipes.
        process = new QProcess();
        QStringList env;
        env << "HOME=" + QString::fromLocal8Bit(std::getenv("HOME"));
        env << "DISPLAY=" + QString::fromLocal8Bit(std::getenv("DISPLAY"));
        process->setEnvironment(env);
        process->setProgram("/bin/sh");
        process->setArguments({"-c", cmd.c_str()});
        process->setProcessChannelMode(QProcess::MergedChannels);

        // Read the output from the process and emit log messages (threaded).
        connect(process, &QProcess::readyReadStandardOutput, this, &LogMessageScroller::read_output);
        connect(process, &QProcess::readyReadStandardError, this, &LogMessageScroller::read_output);
        process->start();
    }

    auto run_dir_process() -> void {
        const auto name = std::string("snetwork.directory-service.") + std::to_string(node_id);
        const auto ds_info = snet::utils::read_file(snet::constants::DIRECTORY_SERVICE_PRIVATE_DIR / (name + ".json"));
        const auto ds_json = nlohmann::json::parse(ds_info);
        const auto key_serialized = ds_json.at("secret_key").get<std::string>();
        const auto key = snet::utils::from_hex<true>(key_serialized);
        const auto cmd = std::string("../snet directory --name ") + name;

        // Create the process and link the logging to pipes.
        process = new QProcess();
        QStringList env;
        env << "HOME=" + QString::fromLocal8Bit(std::getenv("HOME"));
        env << "DISPLAY=" + QString::fromLocal8Bit(std::getenv("DISPLAY"));
        process->setEnvironment(env);
        process->setProgram("/bin/sh");
        process->setArguments({"-c", cmd.c_str()});
        process->setProcessChannelMode(QProcess::MergedChannels);

        // Read the output from the process and emit log messages (threaded).
        connect(process, &QProcess::readyReadStandardOutput, this, &LogMessageScroller::read_output);
        connect(process, &QProcess::readyReadStandardError, this, &LogMessageScroller::read_output);
        process->start();
    }

private slots:
    auto read_output() -> void {
        io_lock.lock();
        const auto process = qobject_cast<QProcess*>(sender());
        while (process->canReadLine()) {
            auto line = process->readLine().toStdString();
            emit recv_new_log_message(std::move(line));
        }
        io_lock.unlock();
    }

signals:
    auto recv_new_log_message(std::string const &message) -> void;
};


class TestGui final : public QWidget {
    Q_OBJECT

public:
    explicit TestGui(QWidget *parent = nullptr) :
        QWidget(parent) {
        setWindowTitle(QString::fromStdString("Test GUI"));
        setLayout(new QGridLayout());

        // Cell for each node.
        auto counter = 0;
        for (auto i = 0; i < H; ++i) {
            for (auto j = 0; j < W; ++j) {
                const auto n = i * W + j;
                LogMessageScroller *log_display;
                if (n < DIR_NODE_COUNT) {
                    log_display = new LogMessageScroller(n, true, this);
                }
                else {
                    log_display = new LogMessageScroller(n - DIR_NODE_COUNT, false, this);
                }
                qobject_cast<QGridLayout*>(layout())->addWidget(log_display, i, j);
                ++counter;
            }
        }
        showMaximized();
    }
};


auto create_directory_services() -> void {
    for (auto const &file : std::filesystem::directory_iterator(snet::constants::DIRECTORY_SERVICE_PRIVATE_DIR)) {
        std::filesystem::permissions(file, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
        std::filesystem::remove(file);
    }
    snet::utils::write_file(snet::constants::DIRECTORY_SERVICE_PUBLIC_FILE, nlohmann::json::object().dump(4));

    for (auto i = 0; i < DIR_NODE_COUNT; ++i) {
        const auto username = std::string("snetwork.directory-service.") + std::to_string(i);
        if (auto info = snet::managers::ds::validate_directory_profile(username); info.has_value()) {
            snet::managers::keys::del_info(std::get<0>(*info));
        }
        snet::managers::ds::create_directory_profile(username);
    }
}


auto create_nodes() -> void {
    for (auto i = 0; i < NODE_COUNT; ++i) {
        const auto username = std::string("node.") + std::to_string(i);
        const auto password = std::string("pass.") + std::to_string(i);
        if (auto info = snet::managers::profile::validate_profile(username, password); info.has_value()) {
            snet::managers::keys::del_info(std::get<0>(*info));
        }
        snet::managers::profile::delete_profile(username, password);
        snet::managers::profile::create_profile(username, password);
    }
}

#define BOOT 0

auto main(int argc, char *argv[]) -> int {
#if BOOT
    create_directory_services();
    create_nodes();
#else
    qputenv("QT_QPA_PLATFORM", QByteArray("xcb"));
    QApplication app(argc, argv);
    const auto gui = new TestGui();
    return QApplication::exec();
#endif
}


#include "test.moc"
