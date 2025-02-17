import { Button, Card, Space, Table } from 'antd'
import React, { useEffect, useState } from 'react'
import { getNoTTLVRequest } from './utils'

interface OwnedObject {
    uid: string;
    type: string;
    state: string;
    createdAt: string;
}

const ObjectsOwnedList: React.FC = () => {
    const [isLoading, setIsLoading] = useState(false);
    const [objects, setObjects] = useState<OwnedObject[]>([]);
    const [res, setRes] = useState<string | undefined>(undefined);

    const columns = [
        {
            title: 'Object UID',
            dataIndex: 'object_id',
            key: 'object_id',
        },
        {
            title: 'Type',
            key: 'attributes.ObjectType',
            render: (_, record) => record.attributes?.ObjectType || 'N/A'

        },
        {
            title: 'State',
            dataIndex: 'state',
            key: 'state',
        }
    ];

    const fetchOwnedObjects = async () => {
        setIsLoading(true);
        setRes(undefined);
        setObjects([])
        try {
            const response = await getNoTTLVRequest("/access/owned");
            if (response.length) {
                setObjects(response);
            } else {
                setRes("Empty result");
            }

        } catch (e) {
            setRes(`Error listing objects: ${e}`)
            console.error("Error listing objects:", e);
        } finally {
            setIsLoading(false);
        }
    };

    useEffect(() => {
        fetchOwnedObjects();
    }, []);

    return (
        <div className="p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">Objects owned</h1>
                <Button
                    type="primary"
                    onClick={fetchOwnedObjects}
                    loading={isLoading}
                    className="bg-black-500 hover:bg-blue-700 border-0"
                >
                    Refresh
                </Button>
            </div>

            <div className="mb-8 space-y-2">
                <p>List of objects you own. </p>
                <p>As an owner, you can perform any operation on these objects and grant access rights to other users.</p>
            </div>
            <Space direction="vertical" size="middle" style={{ display: 'flex' }}>
                <Card>
                    <Table
                        dataSource={objects}
                        columns={columns}
                        rowKey="object_id"
                        loading={isLoading}
                        pagination={{ pageSize: 10 }}
                        className="border rounded"
                    />
                </Card>
            </Space>
            {res && <div>{res}</div>}

        </div>
    );
};

export default ObjectsOwnedList;
