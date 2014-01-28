CREATE DATABASE  IF NOT EXISTS `mdm4all_db` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `mdm4all_db`;
-- MySQL dump 10.13  Distrib 5.6.13, for Linux (x86_64)
--
-- Host: 127.0.0.1    Database: mdm4all_db
-- ------------------------------------------------------
-- Server version	5.1.69

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `CaCertNextSerialNumberTable`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE IF NOT EXISTS `CaCertNextSerialNumberTable` (
  `CaCertNextSerialNumber` int(11) NOT NULL AUTO_INCREMENT COMMENT 'Auto Increment for next CA serial number.',
  PRIMARY KEY (`CaCertNextSerialNumber`),
  UNIQUE KEY `CaCertNextSerialNumberIdx_UNIQUE` (`CaCertNextSerialNumber`)
) ENGINE=InnoDB AUTO_INCREMENT=175 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `CertRevocationsTable`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE IF NOT EXISTS `CertRevocationsTable` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `IssuedCertificateIssuerAndSerialNumber` char(255) NOT NULL,
  `notBefore` date NOT NULL,
  `notAfter` date NOT NULL,
  `x509Crl` char(128) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `IssuedCertificateIssuerAndSerialNumber_UNIQUE` (`IssuedCertificateIssuerAndSerialNumber`),
  CONSTRAINT `fk_CertRevocationsTable_1` FOREIGN KEY (`IssuedCertificateIssuerAndSerialNumber`) REFERENCES `IssuedCertificatesTable` (`IssuedCertificateIssuerAndSerialNumber`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `IssuedCertificatesTable`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE IF NOT EXISTS `IssuedCertificatesTable` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `IssuedCertificateIssuerAndSerialNumber` char(255) NOT NULL,
  `CaRootIssuerAndSerialNumber` char(255) NOT NULL,
  `IssuedCertificatex509Data` blob NOT NULL,
  `IssuedCertificateCrlUrl` char(128) NOT NULL,
  `Enabled` bit(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `IssuedCertificateIssuerAndSerialNumber_UNIQUE` (`IssuedCertificateIssuerAndSerialNumber`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `fk_IssuedCertificatesTable_1_idx` (`CaRootIssuerAndSerialNumber`),
  CONSTRAINT `fk_IssuedCertificatesTable_1` FOREIGN KEY (`CaRootIssuerAndSerialNumber`) REFERENCES `RootCertificateAuthorityTable` (`CaRootIssuerAndSerialNumber`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `RootCertificateAuthorityTable`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE IF NOT EXISTS `RootCertificateAuthorityTable` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `RootCAx509CertData` blob NOT NULL,
  `Rax509CertData` blob NOT NULL,
  `RaPrivateKey` blob NOT NULL,
  `CaRootIssuerAndSerialNumber` char(255) NOT NULL,
  `RaRootIssuerAndSerialNumber` char(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  UNIQUE KEY `CaRootIssuerAndSerialNumber_UNIQUE` (`CaRootIssuerAndSerialNumber`),
  UNIQUE KEY `RaRootIssuerAndSerialNumber_UNIQUE` (`RaRootIssuerAndSerialNumber`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2014-01-12 19:43:46
