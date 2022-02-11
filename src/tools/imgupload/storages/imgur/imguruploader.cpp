// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2017-2019 Alejandro Sirgo Rica & Contributors

#include "imguruploader.h"
#include "src/utils/confighandler.h"
#include "src/utils/filenamehandler.h"
#include "src/utils/history.h"
#include "src/widgets/loadspinner.h"
#include "src/widgets/notificationwidget.h"
#include <QBuffer>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QShortcut>
#include <QUrlQuery>

ImgurUploader::ImgurUploader(const QPixmap& capture, QWidget* parent)
  : ImgUploaderBase(capture, parent)
{
    m_NetworkAM = new QNetworkAccessManager(this);
    connect(m_NetworkAM,
            &QNetworkAccessManager::finished,
            this,
            &ImgurUploader::handleReply);
}

void ImgurUploader::handleReply(QNetworkReply* reply)
{
    spinner()->deleteLater();
    m_currentImageName.clear();
    if (reply->error() == QNetworkReply::NoError) {
        QJsonDocument response = QJsonDocument::fromJson(reply->readAll());
        QJsonObject json = response.object();
        QJsonObject data = json[QStringLiteral("data")].toObject();
        setImageURL(data[QStringLiteral("link")].toString());

        auto deleteToken = data[QStringLiteral("deletehash")].toString();

        // save history
        m_currentImageName = imageURL().toString();
        int lastSlash = m_currentImageName.lastIndexOf("/");
        if (lastSlash >= 0) {
            m_currentImageName = m_currentImageName.mid(lastSlash + 1);
        }

        // save image to history
        History history;
        m_currentImageName =
          history.packFileName("imgur", deleteToken, m_currentImageName);
        history.save(pixmap(), m_currentImageName);

        emit uploadOk(imageURL());
    } else {
        setInfoLabelText(reply->errorString());

        int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        ImgurConf *imgurConfWidget = new ImgurConf(this);

        switch(status) {
            case 401: // Probably unauthorized
                emit imgurConfWidget->authorize(true);
            break;

            case 403: // Probably invalid token
                emit imgurConfWidget->refreshToken();
            break;

            case 429: // Rate limit
                QDateTime wait;
#if QT_VERSION < QT_VERSION_CHECK(5, 8, 0)
                wait.setTime_t(reply->rawHeader("X-RateLimit-UserReset").toInt());
#else
                wait.setSecsSinceEpoch(reply->rawHeader("X-RateLimit-UserReset").toInt());
#endif
                setInfoLabelText(
                    tr("API rate limit reached, you'll need to wait %1 seconds to try again.")
                        .arg(QDateTime::currentDateTimeUtc().secsTo(wait))
                );
            break;
        }
    }
    new QShortcut(Qt::Key_Escape, this, SLOT(close()));
}

void ImgurUploader::upload()
{
    ImgurConfigHandler config;
    QMap<QString, QVariant> token = config.getToken();

    QByteArray byteArray;
    QBuffer buffer(&byteArray);
    pixmap().save(&buffer, "PNG");

    QUrlQuery urlQuery;
    urlQuery.addQueryItem(QStringLiteral("title"), QStringLiteral(""));
    QString description = FileNameHandler().parsedPattern();
    urlQuery.addQueryItem(QStringLiteral("description"), description);

    if (config.isAuthorized() && !config.getSetting(QStringLiteral("anonymous_upload")).toBool()) {
        urlQuery.addQueryItem(QStringLiteral("album"), config.getSetting(QStringLiteral("album"), "").toString());
    }

    QUrl url(QStringLiteral("https://api.imgur.com/3/image"));
    url.setQuery(urlQuery);
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      "application/application/x-www-form-urlencoded");

    // Use bundled client_id by default
    QByteArray authorization = QStringLiteral("Client-ID %1").arg(IMGUR_CLIENT_ID).toUtf8();

    if (config.isAuthorized() && config.getSetting(QStringLiteral("anonymous_upload")).toBool()) {
        // Anonymous upload of authorized application
        authorization = QStringLiteral("Client-ID %1").arg(config.getSetting(QStringLiteral("Api/client_id"), "").toString()).toUtf8();
    } else if (config.isAuthorized()) {
        // Upload image to user account
        authorization = QStringLiteral("Bearer %1").arg(token.value(QStringLiteral("access_token"), "").toString()).toUtf8();
    }

    request.setRawHeader("Authorization", authorization);

    m_NetworkAM->post(request, byteArray);
}

void ImgurUploader::deleteImage(const QString& fileName,
                                const QString& deleteToken)
{
    Q_UNUSED(fileName)
    bool successful = QDesktopServices::openUrl(
      QUrl(QStringLiteral("https://imgur.com/delete/%1").arg(deleteToken)));
    if (!successful) {
        notification()->showMessage(tr("Unable to open the URL."));
    }

    emit deleteOk();
}
